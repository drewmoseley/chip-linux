/*
 * Contains CPU specific errata definitions
 *
 * Copyright (C) 2014 ARM Ltd.
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/types.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/cpufeature.h>

#define MIDR_CORTEX_A53 MIDR_CPU_PART(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A53)
#define MIDR_CORTEX_A57 MIDR_CPU_PART(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A57)
#define MIDR_THUNDERX	MIDR_CPU_PART(ARM_CPU_IMP_CAVIUM, CAVIUM_CPU_PART_THUNDERX)

#define CPU_MODEL_MASK (MIDR_IMPLEMENTOR_MASK | MIDR_PARTNUM_MASK | \
			MIDR_ARCHITECTURE_MASK)

static bool __maybe_unused
is_affected_midr_range(const struct arm64_cpu_capabilities *entry)
{
	u32 midr = read_cpuid_id();

	if (!entry->matches(entry, SCOPE_LOCAL_CPU))
		return;

	if (psci_ops.smccc_version == SMCCC_VERSION_1_0)
		return;

	switch (psci_ops.conduit) {
	case PSCI_CONDUIT_HVC:
		arm_smccc_1_1_hvc(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
				  ARM_SMCCC_ARCH_WORKAROUND_1, &res);
		if ((int)res.a0 < 0)
			return;
		cb = call_hvc_arch_workaround_1;
		/* This is a guest, no need to patch KVM vectors */
		smccc_start = NULL;
		smccc_end = NULL;
		break;

	case PSCI_CONDUIT_SMC:
		arm_smccc_1_1_smc(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
				  ARM_SMCCC_ARCH_WORKAROUND_1, &res);
		if ((int)res.a0 < 0)
			return;
		cb = call_smc_arch_workaround_1;
		smccc_start = __smccc_workaround_1_smc_start;
		smccc_end = __smccc_workaround_1_smc_end;
		break;

	default:
		return;
	}

	if (((midr & MIDR_CPU_MODEL_MASK) == MIDR_QCOM_FALKOR) ||
	    ((midr & MIDR_CPU_MODEL_MASK) == MIDR_QCOM_FALKOR_V1))
		cb = qcom_link_stack_sanitization;

	install_bp_hardening_cb(entry, cb, smccc_start, smccc_end);

	return;
}
#endif	/* CONFIG_HARDEN_BRANCH_PREDICTOR */

#ifdef CONFIG_ARM64_SSBD
void __init arm64_update_smccc_conduit(struct alt_instr *alt,
				       __le32 *origptr, __le32 *updptr,
				       int nr_inst)
{
	u32 insn;

	BUG_ON(nr_inst != 1);

	switch (psci_ops.conduit) {
	case PSCI_CONDUIT_HVC:
		insn = aarch64_insn_get_hvc_value();
		break;
	case PSCI_CONDUIT_SMC:
		insn = aarch64_insn_get_smc_value();
		break;
	default:
		return;
	}

	*updptr = cpu_to_le32(insn);
}
#endif	/* CONFIG_ARM64_SSBD */

#define CAP_MIDR_RANGE(model, v_min, r_min, v_max, r_max)	\
	.matches = is_affected_midr_range,			\
	.midr_range = MIDR_RANGE(model, v_min, r_min, v_max, r_max)

#define CAP_MIDR_ALL_VERSIONS(model)					\
	.matches = is_affected_midr_range,				\
	.midr_range = MIDR_ALL_VERSIONS(model)

#define MIDR_FIXED(rev, revidr_mask) \
	.fixed_revs = (struct arm64_midr_revidr[]){{ (rev), (revidr_mask) }, {}}

#define ERRATA_MIDR_RANGE(model, v_min, r_min, v_max, r_max)		\
	.type = ARM64_CPUCAP_LOCAL_CPU_ERRATUM,				\
	CAP_MIDR_RANGE(model, v_min, r_min, v_max, r_max)

#define CAP_MIDR_RANGE_LIST(list)				\
	.matches = is_affected_midr_range_list,			\
	.midr_range_list = list

/* Errata affecting a range of revisions of  given model variant */
#define ERRATA_MIDR_REV_RANGE(m, var, r_min, r_max)	 \
	ERRATA_MIDR_RANGE(m, var, r_min, var, r_max)

/* Errata affecting a single variant/revision of a model */
#define ERRATA_MIDR_REV(model, var, rev)	\
	ERRATA_MIDR_RANGE(model, var, rev, var, rev)

/* Errata affecting all variants/revisions of a given a model */
#define ERRATA_MIDR_ALL_VERSIONS(model)				\
	.type = ARM64_CPUCAP_LOCAL_CPU_ERRATUM,			\
	CAP_MIDR_ALL_VERSIONS(model)

/* Errata affecting a list of midr ranges, with same work around */
#define ERRATA_MIDR_RANGE_LIST(midr_list)			\
	.type = ARM64_CPUCAP_LOCAL_CPU_ERRATUM,			\
	CAP_MIDR_RANGE_LIST(midr_list)

/*
 * Generic helper for handling capabilties with multiple (match,enable) pairs
 * of call backs, sharing the same capability bit.
 * Iterate over each entry to see if at least one matches.
 */
static bool __maybe_unused
multi_entry_cap_matches(const struct arm64_cpu_capabilities *entry, int scope)
{
	const struct arm64_cpu_capabilities *caps;

	for (caps = entry->match_list; caps->matches; caps++)
		if (caps->matches(caps, scope))
			return true;

	return false;
}

	midr &= MIDR_REVISION_MASK | MIDR_VARIANT_MASK;

	return (midr >= entry->midr_range_min && midr <= entry->midr_range_max);
}

#define MIDR_RANGE(model, min, max) \
	.matches = is_affected_midr_range, \
	.midr_model = model, \
	.midr_range_min = min, \
	.midr_range_max = max

const struct arm64_cpu_capabilities arm64_errata[] = {
#if	defined(CONFIG_ARM64_ERRATUM_826319) || \
	defined(CONFIG_ARM64_ERRATUM_827319) || \
	defined(CONFIG_ARM64_ERRATUM_824069)
	{
	/* Cortex-A53 r0p[012] */
		.desc = "ARM errata 826319, 827319, 824069",
		.capability = ARM64_WORKAROUND_CLEAN_CACHE,
		MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x02),
	},
#endif
#ifdef CONFIG_ARM64_ERRATUM_819472
	{
	/* Cortex-A53 r0p[01] */
		.desc = "ARM errata 819472",
		.capability = ARM64_WORKAROUND_CLEAN_CACHE,
		MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x01),
	},
#endif
#ifdef CONFIG_ARM64_ERRATUM_832075
	{
	/* Cortex-A57 r0p0 - r1p2 */
		.desc = "ARM erratum 832075",
		.capability = ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE,
		MIDR_RANGE(MIDR_CORTEX_A57, 0x00,
			   (1 << MIDR_VARIANT_SHIFT) | 2),
	},
#endif
#ifdef CONFIG_ARM64_ERRATUM_834220
	{
	/* Cortex-A57 r0p0 - r1p2 */
		.desc = "ARM erratum 834220",
		.capability = ARM64_WORKAROUND_834220,
		MIDR_RANGE(MIDR_CORTEX_A57, 0x00,
			   (1 << MIDR_VARIANT_SHIFT) | 2),
	},
#endif
#ifdef CONFIG_ARM64_ERRATUM_845719
	{
	/* Cortex-A53 r0p[01234] */
		.desc = "ARM erratum 845719",
		.capability = ARM64_WORKAROUND_845719,
		MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x04),
	},
#endif
#ifdef CONFIG_CAVIUM_ERRATUM_23154
	{
	/* Cavium ThunderX, pass 1.x */
		.desc = "Cavium erratum 23154",
		.capability = ARM64_WORKAROUND_CAVIUM_23154,
		MIDR_RANGE(MIDR_THUNDERX, 0x00, 0x01),
	},
#endif
	{
	}
};

void check_local_cpu_errata(void)
{
	update_cpu_capabilities(arm64_errata, "enabling workaround for");
}
