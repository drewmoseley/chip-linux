/*
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/cpu.h>
#include <linux/of_irq.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>

#include <clocksource/arm_arch_timer.h>
#include <asm/arch_timer.h>

#include <kvm/arm_vgic.h>
#include <kvm/arm_arch_timer.h>

#include "trace.h"

static struct timecounter *timecounter;
static struct workqueue_struct *wqueue;
static unsigned int host_vtimer_irq;

static cycle_t kvm_phys_timer_read(void)
{
	return timecounter->cc->read(timecounter->cc);
}

static bool timer_is_armed(struct arch_timer_cpu *timer)
{
	return timer->armed;
}

/* timer_arm: as in "arm the timer", not as in ARM the company */
static void timer_arm(struct arch_timer_cpu *timer, u64 ns)
{
	timer->armed = true;
	hrtimer_start(&timer->timer, ktime_add_ns(ktime_get(), ns),
		      HRTIMER_MODE_ABS);
}

static void timer_disarm(struct arch_timer_cpu *timer)
{
	if (timer_is_armed(timer)) {
		hrtimer_cancel(&timer->timer);
		cancel_work_sync(&timer->expired);
		timer->armed = false;
	}
}

static irqreturn_t kvm_arch_timer_handler(int irq, void *dev_id)
{
	struct kvm_vcpu *vcpu = *(struct kvm_vcpu **)dev_id;

	/*
	 * We disable the timer in the world switch and let it be
	 * handled by kvm_timer_sync_hwstate(). Getting a timer
	 * interrupt at this point is a sure sign of some major
	 * breakage.
	 */
	pr_warn("Unexpected interrupt %d on vcpu %p\n", irq, vcpu);
	return IRQ_HANDLED;
}

/*
 * Work function for handling the backup timer that we schedule when a vcpu is
 * no longer running, but had a timer programmed to fire in the future.
 */
static void kvm_timer_inject_irq_work(struct work_struct *work)
{
	struct kvm_vcpu *vcpu;

	vcpu = container_of(work, struct kvm_vcpu, arch.timer_cpu.expired);
	vcpu->arch.timer_cpu.armed = false;

	WARN_ON(!kvm_timer_should_fire(vcpu));

	/*
	 * If the vcpu is blocked we want to wake it up so that it will see
	 * the timer has expired when entering the guest.
	 */
	kvm_vcpu_kick(vcpu);
}

static u64 kvm_timer_compute_delta(struct kvm_vcpu *vcpu)
{
	cycle_t cval, now;

	cval = vcpu->arch.timer_cpu.cntv_cval;
	now = kvm_phys_timer_read() - vcpu->kvm->arch.timer.cntvoff;

	if (now < cval) {
		u64 ns;

		ns = cyclecounter_cyc2ns(timecounter->cc,
					 cval - now,
					 timecounter->mask,
					 &timecounter->frac);
		return ns;
	}

	return 0;
}

static enum hrtimer_restart kvm_timer_expire(struct hrtimer *hrt)
{
	struct arch_timer_cpu *timer;
	struct kvm_vcpu *vcpu;
	u64 ns;

	timer = container_of(hrt, struct arch_timer_cpu, timer);
	vcpu = container_of(timer, struct kvm_vcpu, arch.timer_cpu);

	/*
	 * Check that the timer has really expired from the guest's
	 * PoV (NTP on the host may have forced it to expire
	 * early). If we should have slept longer, restart it.
	 */
	ns = kvm_timer_compute_delta(vcpu);
	if (unlikely(ns)) {
		hrtimer_forward_now(hrt, ns_to_ktime(ns));
		return HRTIMER_RESTART;
	}

	queue_work(wqueue, &timer->expired);
	return HRTIMER_NORESTART;
}

static bool kvm_timer_irq_can_fire(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	return !(timer->cntv_ctl & ARCH_TIMER_CTRL_IT_MASK) &&
		(timer->cntv_ctl & ARCH_TIMER_CTRL_ENABLE);
}

bool kvm_timer_should_fire(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	cycle_t cval, now;

	if (!kvm_timer_irq_can_fire(vcpu))
		return false;

	cval = timer->cntv_cval;
	now = kvm_phys_timer_read() - vcpu->kvm->arch.timer.cntvoff;

	return cval <= now;
}

static void kvm_timer_update_irq(struct kvm_vcpu *vcpu, bool new_level)
{
	int ret;
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	BUG_ON(!vgic_initialized(vcpu->kvm));

	timer->irq.level = new_level;
	trace_kvm_timer_update_irq(vcpu->vcpu_id, timer->map->virt_irq,
				   timer->irq.level);
	ret = kvm_vgic_inject_mapped_irq(vcpu->kvm, vcpu->vcpu_id,
					 timer->map,
					 timer->irq.level);
	WARN_ON(ret);
}

/*
 * Check if there was a change in the timer state (should we raise or lower
 * the line level to the GIC).
 */
static int kvm_timer_update_state(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	/*
	 * If userspace modified the timer registers via SET_ONE_REG before
	 * the vgic was initialized, we mustn't set the timer->irq.level value
	 * because the guest would never see the interrupt.  Instead wait
	 * until we call this function from kvm_timer_flush_hwstate.
	 */
	if (!vgic_initialized(vcpu->kvm))
		return -ENODEV;

	if (kvm_timer_should_fire(vcpu) != timer->irq.level)
		kvm_timer_update_irq(vcpu, !timer->irq.level);

	return 0;
}

static void timer_save_state(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);

	if (timer->enabled) {
		vtimer->cnt_ctl = read_sysreg_el0(cntv_ctl);
		vtimer->cnt_cval = read_sysreg_el0(cntv_cval);
	}

	/* Disable the virtual timer */
	write_sysreg_el0(0, cntv_ctl);
}

/*
 * Schedule the background timer before calling kvm_vcpu_block, so that this
 * thread is removed from its waitqueue and made runnable when there's a timer
 * interrupt to handle.
 */
void kvm_timer_schedule(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	BUG_ON(timer_is_armed(timer));

	/*
	 * No need to schedule a background timer if the guest timer has
	 * already expired, because kvm_vcpu_block will return before putting
	 * the thread to sleep.
	 */
	if (kvm_timer_should_fire(vcpu))
		return;

	/*
	 * If the timer is not capable of raising interrupts (disabled or
	 * masked), then there's no more work for us to do.
	 */
	if (!kvm_timer_irq_can_fire(vcpu))
		return;

	/*  The timer has not yet expired, schedule a background timer */
	timer_arm(timer, kvm_timer_compute_delta(vcpu));
}

static void timer_restore_state(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);

	if (timer->enabled) {
		write_sysreg_el0(vtimer->cnt_cval, cntv_cval);
		isb();
		write_sysreg_el0(vtimer->cnt_ctl, cntv_ctl);
	}
}

void kvm_timer_unschedule(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	timer_disarm(timer);
}

static void set_cntvoff(u64 cntvoff)
{
	u32 low = lower_32_bits(cntvoff);
	u32 high = upper_32_bits(cntvoff);

	/*
	 * Since kvm_call_hyp doesn't fully support the ARM PCS especially on
	 * 32-bit systems, but rather passes register by register shifted one
	 * place (we put the function address in r0/x0), we cannot simply pass
	 * a 64-bit value as an argument, but have to split the value in two
	 * 32-bit halves.
	 */
	kvm_call_hyp(__kvm_timer_set_cntvoff, low, high);
}

static void kvm_timer_flush_hwstate_vgic(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	bool phys_active;
	int ret;

	if (kvm_timer_update_state(vcpu))
		return;

	/*
	* If we enter the guest with the virtual input level to the VGIC
	* asserted, then we have already told the VGIC what we need to, and
	* we don't need to exit from the guest until the guest deactivates
	* the already injected interrupt, so therefore we should set the
	* hardware active state to prevent unnecessary exits from the guest.
	*
	* Also, if we enter the guest with the virtual timer interrupt active,
	* then it must be active on the physical distributor, because we set
	* the HW bit and the guest must be able to deactivate the virtual and
	* physical interrupt at the same time.
	*
	* Conversely, if the virtual input level is deasserted and the virtual
	* interrupt is not active, then always clear the hardware active state
	* to ensure that hardware interrupts from the timer triggers a guest
	* exit.
	*/
	if (timer->irq.level || kvm_vgic_map_is_active(vcpu, timer->map))
		phys_active = true;
	else
		phys_active = false;

	ret = irq_set_irqchip_state(timer->map->irq,
				    IRQCHIP_STATE_ACTIVE,
				    phys_active);
	WARN_ON(ret);

	vtimer->active_cleared_last = !phys_active;
}

bool kvm_timer_should_notify_user(struct kvm_vcpu *vcpu)
{
	struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);
	struct arch_timer_context *ptimer = vcpu_ptimer(vcpu);
	struct kvm_sync_regs *sregs = &vcpu->run->s.regs;
	bool vlevel, plevel;

	if (likely(irqchip_in_kernel(vcpu->kvm)))
		return false;

	vlevel = sregs->device_irq_level & KVM_ARM_DEV_EL1_VTIMER;
	plevel = sregs->device_irq_level & KVM_ARM_DEV_EL1_PTIMER;

	return vtimer->irq.level != vlevel ||
	       ptimer->irq.level != plevel;
}

static void kvm_timer_flush_hwstate_user(struct kvm_vcpu *vcpu)
{
	struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);

	/*
	 * To prevent continuously exiting from the guest, we mask the
	 * physical interrupt such that the guest can make forward progress.
	 * Once we detect the output level being deasserted, we unmask the
	 * interrupt again so that we exit from the guest when the timer
	 * fires.
	*/
	if (vtimer->irq.level)
		disable_percpu_irq(host_vtimer_irq);
	else
		enable_percpu_irq(host_vtimer_irq, 0);
}

/**
 * kvm_timer_flush_hwstate - prepare timers before running the vcpu
 * @vcpu: The vcpu pointer
 *
 * Check if the virtual timer has expired while we were running in the host,
 * and inject an interrupt if that was the case, making sure the timer is
 * masked or disabled on the host so that we keep executing.  Also schedule a
 * software timer for the physical timer if it is enabled.
 */
void kvm_timer_flush_hwstate(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);

	if (unlikely(!timer->enabled))
		return;

	kvm_timer_update_state(vcpu);

	/* Set the background timer for the physical timer emulation. */
	phys_timer_emulate(vcpu, vcpu_ptimer(vcpu));

	if (unlikely(!irqchip_in_kernel(vcpu->kvm)))
		kvm_timer_flush_hwstate_user(vcpu);
	else
		kvm_timer_flush_hwstate_vgic(vcpu);

	set_cntvoff(vtimer->cntvoff);
	timer_restore_state(vcpu);
}

/**
 * kvm_timer_sync_hwstate - sync timer state from cpu
 * @vcpu: The vcpu pointer
 *
 * Check if the virtual timer has expired while we were running in the guest,
 * and inject an interrupt if that was the case.
 */
void kvm_timer_sync_hwstate(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	BUG_ON(timer_is_armed(timer));

	timer_save_state(vcpu);
	set_cntvoff(0);

	/*
	 * The guest could have modified the timer registers or the timer
	 * could have expired, update the timer state.
	 */
	kvm_timer_update_state(vcpu);
}

int kvm_timer_vcpu_reset(struct kvm_vcpu *vcpu,
			 const struct kvm_irq_level *irq)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	struct irq_phys_map *map;

	/*
	 * The vcpu timer irq number cannot be determined in
	 * kvm_timer_vcpu_init() because it is called much before
	 * kvm_vcpu_set_target(). To handle this, we determine
	 * vcpu timer irq number when the vcpu is reset.
	 */
	timer->irq.irq = irq->irq;

	/*
	 * The bits in CNTV_CTL are architecturally reset to UNKNOWN for ARMv8
	 * and to 0 for ARMv7.  We provide an implementation that always
	 * resets the timer to be disabled and unmasked and is compliant with
	 * the ARMv7 architecture.
	 */
	timer->cntv_ctl = 0;
	kvm_timer_update_state(vcpu);

	/*
	 * Tell the VGIC that the virtual interrupt is tied to a
	 * physical interrupt. We do that once per VCPU.
	 */
	map = kvm_vgic_map_phys_irq(vcpu, irq->irq, host_vtimer_irq);
	if (WARN_ON(IS_ERR(map)))
		return PTR_ERR(map);

	timer->map = map;
	return 0;
}

void kvm_timer_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	INIT_WORK(&timer->expired, kvm_timer_inject_irq_work);
	hrtimer_init(&timer->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	timer->timer.function = kvm_timer_expire;
}

static void kvm_timer_init_interrupt(void *info)
{
	enable_percpu_irq(host_vtimer_irq, 0);
}

int kvm_arm_timer_set_reg(struct kvm_vcpu *vcpu, u64 regid, u64 value)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	switch (regid) {
	case KVM_REG_ARM_TIMER_CTL:
		timer->cntv_ctl = value;
		break;
	case KVM_REG_ARM_TIMER_CNT:
		vcpu->kvm->arch.timer.cntvoff = kvm_phys_timer_read() - value;
		break;
	case KVM_REG_ARM_TIMER_CVAL:
		timer->cntv_cval = value;
		break;
	default:
		return -1;
	}

	kvm_timer_update_state(vcpu);
	return 0;
}

u64 kvm_arm_timer_get_reg(struct kvm_vcpu *vcpu, u64 regid)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	switch (regid) {
	case KVM_REG_ARM_TIMER_CTL:
		return timer->cntv_ctl;
	case KVM_REG_ARM_TIMER_CNT:
		return kvm_phys_timer_read() - vcpu->kvm->arch.timer.cntvoff;
	case KVM_REG_ARM_TIMER_CVAL:
		return timer->cntv_cval;
	}
	return (u64)-1;
}

static int kvm_timer_cpu_notify(struct notifier_block *self,
				unsigned long action, void *cpu)
{
	switch (action) {
	case CPU_STARTING:
	case CPU_STARTING_FROZEN:
		kvm_timer_init_interrupt(NULL);
		break;
	case CPU_DYING:
	case CPU_DYING_FROZEN:
		disable_percpu_irq(host_vtimer_irq);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block kvm_timer_cpu_nb = {
	.notifier_call = kvm_timer_cpu_notify,
};

static const struct of_device_id arch_timer_of_match[] = {
	{ .compatible	= "arm,armv7-timer",	},
	{ .compatible	= "arm,armv8-timer",	},
	{},
};

int kvm_timer_hyp_init(void)
{
	struct device_node *np;
	unsigned int ppi;
	int err;

	timecounter = arch_timer_get_timecounter();
	if (!timecounter)
		return -ENODEV;

	np = of_find_matching_node(NULL, arch_timer_of_match);
	if (!np) {
		kvm_err("kvm_arch_timer: can't find DT node\n");
		return -ENODEV;
	}

	ppi = irq_of_parse_and_map(np, 2);
	if (!ppi) {
		kvm_err("kvm_arch_timer: no virtual timer interrupt\n");
		err = -EINVAL;
		goto out;
	}

	err = request_percpu_irq(ppi, kvm_arch_timer_handler,
				 "kvm guest timer", kvm_get_running_vcpus());
	if (err) {
		kvm_err("kvm_arch_timer: can't request interrupt %d (%d)\n",
			ppi, err);
		goto out;
	}

	host_vtimer_irq = ppi;

	err = __register_cpu_notifier(&kvm_timer_cpu_nb);
	if (err) {
		kvm_err("Cannot register timer CPU notifier\n");
		goto out_free;
	}

	wqueue = create_singlethread_workqueue("kvm_arch_timer");
	if (!wqueue) {
		err = -ENOMEM;
		goto out_free;
	}

	kvm_info("%s IRQ%d\n", np->name, ppi);
	on_each_cpu(kvm_timer_init_interrupt, NULL, 1);

	goto out;
out_free:
	free_percpu_irq(ppi, kvm_get_running_vcpus());
out:
	of_node_put(np);
	return err;
}

void kvm_timer_vcpu_terminate(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	timer_disarm(timer);
	if (timer->map)
		kvm_vgic_unmap_phys_irq(vcpu, timer->map);
}

void kvm_timer_enable(struct kvm *kvm)
{
	if (kvm->arch.timer.enabled)
		return;

	/*
	 * There is a potential race here between VCPUs starting for the first
	 * time, which may be enabling the timer multiple times.  That doesn't
	 * hurt though, because we're just setting a variable to the same
	 * variable that it already was.  The important thing is that all
	 * VCPUs have the enabled variable set, before entering the guest, if
	 * the arch timers are enabled.
	 */
	if (timecounter && wqueue)
		kvm->arch.timer.enabled = 1;
}

void kvm_timer_init(struct kvm *kvm)
{
	kvm->arch.timer.cntvoff = kvm_phys_timer_read();
}
