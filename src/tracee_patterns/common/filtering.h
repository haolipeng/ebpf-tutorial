// SPDX-License-Identifier: GPL-2.0
// Tracee 编程技巧示例 - 位图过滤器
// 展示: 使用位图高效评估多策略匹配

#ifndef __FILTERING_H__
#define __FILTERING_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "types.h"
#include "maps.h"

//============================================================================
// 技巧: 位图策略过滤
//
// 核心思想:
// - 使用 64 位整数表示 64 个策略的启用/匹配状态
// - 每个策略占用一个 bit
// - 通过位运算同时评估所有策略，避免循环
//============================================================================

// 过滤器未设置时的默认值
#define FILTER_MAX_NOT_SET 0
#define FILTER_MIN_NOT_SET (~0ULL)

//============================================================================
// 技巧 1: 相等性过滤器
//
// 场景:
//   policy 1: uid=1000          (等于)
//   policy 2: uid=2000          (等于)
//   policy 3: uid!=1000         (不等于)
//
// equals_in_policies: 哪些策略使用 "等于" 操作并匹配
// key_used_in_policies: 哪些策略使用了当前 key
// match_if_key_missing: 哪些策略在 key 不存在时默认匹配
//============================================================================

statfunc u64 equality_filter_matches(u64 match_if_key_missing,
                                      void *filter_map,
                                      void *key)
{
    u64 equals_in_policies = 0;
    u64 key_used_in_policies = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, key);
        if (equality != NULL) {
            equals_in_policies = equality->equals_in_policies;
            key_used_in_policies = equality->key_used_in_policies;
        }
    }

    // 匹配逻辑:
    // 1. equals_in_policies: key 存在且匹配 "等于" 的策略
    // 2. match_if_key_missing & ~key_used_in_policies:
    //    key 不存在且默认匹配的策略 (排除使用此 key 的策略)
    return equals_in_policies | (match_if_key_missing & ~key_used_in_policies);
}

//============================================================================
// 技巧 2: 范围过滤器 (用于 UID/PID 范围检查)
//============================================================================

statfunc u64 range_filter_matches(u64 match_if_key_missing,
                                   void *filter_map,
                                   u64 value,
                                   u64 max_val,
                                   u64 min_val)
{
    u64 equals_in_policies = 0;
    u64 key_used_in_policies = 0;

    if (filter_map) {
        u32 val32 = (u32)value;
        eq_t *equality = bpf_map_lookup_elem(filter_map, &val32);
        if (equality != NULL) {
            equals_in_policies = equality->equals_in_policies;
            key_used_in_policies = equality->key_used_in_policies;
        }
    }

    // 范围检查: 超出范围时只返回精确匹配的策略
    if ((max_val != FILTER_MAX_NOT_SET) && (value >= max_val))
        return equals_in_policies;

    if ((min_val != FILTER_MIN_NOT_SET) && (value <= min_val))
        return equals_in_policies;

    return equals_in_policies | (match_if_key_missing & ~key_used_in_policies);
}

//============================================================================
// 技巧 3: 布尔过滤器 (container=true/false)
//============================================================================

statfunc u64 bool_filter_matches(u64 match_bitmap, bool bool_value)
{
    // match_bitmap: 哪些策略在 bool_value=false 时匹配
    //
    // 如果 bool_value = true:
    //   返回 match_bitmap ^ ~0ULL = ~match_bitmap
    //   (匹配所有 "要求 true" 的策略)
    //
    // 如果 bool_value = false:
    //   返回 match_bitmap ^ 0 = match_bitmap
    //   (匹配所有 "要求 false" 的策略)
    return match_bitmap ^ (bool_value ? ~0ULL : 0);
}

//============================================================================
// 技巧 4: 综合 scope 过滤器
// 将多个过滤条件组合评估
//============================================================================

// 策略配置 (简化版)
typedef struct policies_config {
    // 各过滤器的启用位图
    u64 uid_filter_enabled;
    u64 pid_filter_enabled;
    u64 comm_filter_enabled;
    u64 container_filter_enabled;

    // 各过滤器在 key 缺失时的默认匹配位图
    u64 uid_filter_match_if_missing;
    u64 pid_filter_match_if_missing;
    u64 comm_filter_match_if_missing;
    u64 container_filter_match_if_missing;

    // 范围限制
    u64 uid_max;
    u64 uid_min;
    u64 pid_max;
    u64 pid_min;

    // 所有启用的策略
    u64 enabled_policies;
} policies_config_t;

// 匹配 scope 过滤器
statfunc u64 match_scope_filters(task_context_t *ctx,
                                  policies_config_t *cfg,
                                  u16 version,
                                  bool in_container)
{
    // 初始化: 所有策略都匹配
    u64 res = ~0ULL;

    //--------------------------------------------------------------------
    // 1. 容器过滤器 (不使用 map，直接位运算)
    //--------------------------------------------------------------------
    if (cfg->container_filter_enabled) {
        u64 match_bitmap = cfg->container_filter_match_if_missing;
        u64 mask = ~cfg->container_filter_enabled;

        // 对于未启用此过滤器的策略，使用 mask 保持其匹配状态
        res &= bool_filter_matches(match_bitmap, in_container) | mask;
    }

    //--------------------------------------------------------------------
    // 2. UID 过滤器
    //--------------------------------------------------------------------
    if (cfg->uid_filter_enabled) {
        u64 match_if_missing = cfg->uid_filter_match_if_missing;
        u64 mask = ~cfg->uid_filter_enabled;

        void *filter_map = get_filter_map(&uid_filter_version, version);
        res &= range_filter_matches(match_if_missing, filter_map,
                                    ctx->uid, cfg->uid_max, cfg->uid_min) | mask;
    }

    //--------------------------------------------------------------------
    // 3. PID 过滤器
    //--------------------------------------------------------------------
    if (cfg->pid_filter_enabled) {
        u64 match_if_missing = cfg->pid_filter_match_if_missing;
        u64 mask = ~cfg->pid_filter_enabled;

        void *filter_map = get_filter_map(&uid_filter_version, version);
        // 检查 PID 和 TID
        res &= (range_filter_matches(match_if_missing, filter_map,
                                     ctx->host_pid, cfg->pid_max, cfg->pid_min) |
                range_filter_matches(match_if_missing, filter_map,
                                     ctx->host_tid, cfg->pid_max, cfg->pid_min) |
                mask);
    }

    //--------------------------------------------------------------------
    // 4. 进程名过滤器
    //--------------------------------------------------------------------
    if (cfg->comm_filter_enabled) {
        u64 match_if_missing = cfg->comm_filter_match_if_missing;
        u64 mask = ~cfg->comm_filter_enabled;

        void *filter_map = get_filter_map(&comm_filter_version, version);

        // 需要将 comm 转换为 string_filter_t
        string_filter_t comm_key = {};
        __builtin_memcpy(comm_key.str, ctx->comm, sizeof(comm_key.str));

        res &= equality_filter_matches(match_if_missing, filter_map, &comm_key) | mask;
    }

    //--------------------------------------------------------------------
    // 最终: 只返回启用的策略
    //--------------------------------------------------------------------
    return res & cfg->enabled_policies;
}

//============================================================================
// 技巧 5: 检查是否有策略匹配
//============================================================================

statfunc bool policies_matched(u64 matched_policies)
{
    return matched_policies != 0;
}

// 获取匹配的第一个策略 ID (0-63)
statfunc int get_first_matched_policy(u64 matched_policies)
{
    if (matched_policies == 0)
        return -1;

    // 使用内置函数找到第一个设置的位
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (matched_policies & (1ULL << i))
            return i;
    }
    return -1;
}

//============================================================================
// 技巧 6: 数据过滤器 (基于事件参数的过滤)
// 用于对字符串参数进行精确/前缀/后缀匹配
//============================================================================

// 字符串过滤器配置
typedef struct string_filter_config {
    u64 exact_enabled;           // 精确匹配启用的策略
    u64 prefix_enabled;          // 前缀匹配启用的策略
    u64 suffix_enabled;          // 后缀匹配启用的策略
    u64 exact_match_if_missing;
    u64 prefix_match_if_missing;
    u64 suffix_match_if_missing;
} string_filter_config_t;

//============================================================================
// 示例: 如何在用户空间设置过滤器
//
// // 策略 0: 只追踪 UID=1000 的进程
// policies_config.uid_filter_enabled |= (1ULL << 0);
// eq_t eq = { .equals_in_policies = (1ULL << 0), .key_used_in_policies = (1ULL << 0) };
// bpf_map_update_elem(uid_filter_fd, &uid_1000, &eq, BPF_ANY);
//
// // 策略 1: 追踪除了 root 以外的所有用户
// policies_config.uid_filter_enabled |= (1ULL << 1);
// policies_config.uid_filter_match_if_missing |= (1ULL << 1);  // 默认匹配
// eq_t eq_root = { .equals_in_policies = 0, .key_used_in_policies = (1ULL << 1) };
// bpf_map_update_elem(uid_filter_fd, &uid_0, &eq_root, BPF_ANY);  // root 不匹配
//============================================================================

#endif // __FILTERING_H__
