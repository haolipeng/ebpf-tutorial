import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'eBPF Tutorial',
  description: 'Learn eBPF programming from scratch',
  base: '/ebpf-tutorial/',

  head: [
    ['link', { rel: 'icon', href: '/ebpf-tutorial/favicon.ico' }]
  ],

  // 多语言配置
  locales: {
    root: {
      label: 'English',
      lang: 'en',
      themeConfig: {
        nav: [
          { text: 'Home', link: '/' },
          { text: 'Guide', link: '/guide/lesson-1-helloworld' }
        ],
        sidebar: {
          '/guide/': [
            {
              text: 'Getting Started',
              items: [
                { text: 'Lesson 1: Hello World', link: '/guide/lesson-1-helloworld' }
              ]
            },
            {
              text: 'Hook Mechanisms',
              items: [
                { text: 'Lesson 2: Kprobe', link: '/guide/lesson-2-kprobe' },
                { text: 'Lesson 3: Uprobe', link: '/guide/lesson-3-uprobe' },
                { text: 'Lesson 8: Tracepoint', link: '/guide/lesson-8-tracepoint' },
                { text: 'Lesson 9: Raw Tracepoint', link: '/guide/lesson-9-raw-tracepoint' }
              ]
            },
            {
              text: 'Data Structures',
              items: [
                { text: 'Lesson 4: User Map', link: '/guide/lesson-4-user-map' },
                { text: 'Lesson 5: Kernel User Map', link: '/guide/lesson-5-kernel-user-map' },
                { text: 'Lesson 7: Ring/Perf Buffer', link: '/guide/lesson-7-ringbuffer-perfbuffer' }
              ]
            },
            {
              text: 'Network Programming',
              items: [
                { text: 'Lesson 11: TC Ingress', link: '/guide/lesson-11-tc-ingress' },
                { text: 'Lesson 12: TC Egress', link: '/guide/lesson-12-tc-egress' }
              ]
            },
            {
              text: 'Advanced Topics',
              items: [
                { text: 'Lesson 6: Go Development', link: '/guide/lesson-6-golang-develop' },
                { text: 'Lesson 10: BTF', link: '/guide/lesson-10-btf' },
                { text: 'Lesson 13: SSL Sniff', link: '/guide/lesson-13-ssl-sniff' }
              ]
            }
          ]
        }
      }
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      link: '/zh/',
      themeConfig: {
        nav: [
          { text: '首页', link: '/zh/' },
          { text: '教程', link: '/zh/guide/lesson-1-helloworld' }
        ],
        sidebar: {
          '/zh/guide/': [
            {
              text: '快速开始',
              items: [
                { text: 'Lesson 1: Hello World', link: '/zh/guide/lesson-1-helloworld' }
              ]
            },
            {
              text: 'Hook 机制',
              items: [
                { text: 'Lesson 2: Kprobe', link: '/zh/guide/lesson-2-kprobe' },
                { text: 'Lesson 3: Uprobe', link: '/zh/guide/lesson-3-uprobe' },
                { text: 'Lesson 8: Tracepoint', link: '/zh/guide/lesson-8-tracepoint' },
                { text: 'Lesson 9: Raw Tracepoint', link: '/zh/guide/lesson-9-raw-tracepoint' }
              ]
            },
            {
              text: '数据结构',
              items: [
                { text: 'Lesson 4: 用户态 Map', link: '/zh/guide/lesson-4-user-map' },
                { text: 'Lesson 5: 内核态 Map', link: '/zh/guide/lesson-5-kernel-user-map' },
                { text: 'Lesson 7: Ring/Perf Buffer', link: '/zh/guide/lesson-7-ringbuffer-perfbuffer' }
              ]
            },
            {
              text: '网络编程',
              items: [
                { text: 'Lesson 11: TC Ingress', link: '/zh/guide/lesson-11-tc-ingress' },
                { text: 'Lesson 12: TC Egress', link: '/zh/guide/lesson-12-tc-egress' },
                { text: 'Lesson 17: XDP 过滤', link: '/zh/guide/lesson-17-xdp-filter' }
              ]
            },
            {
              text: '高级主题',
              items: [
                { text: 'Lesson 6: Go 语言开发', link: '/zh/guide/lesson-6-golang-develop' },
                { text: 'Lesson 10: BTF', link: '/zh/guide/lesson-10-btf' },
                { text: 'Lesson 13: SSL Sniff', link: '/zh/guide/lesson-13-ssl-sniff' }
              ]
            },
            {
              text: '实战项目',
              items: [
                { text: 'Lesson 14: HTTPS 流量监控', link: '/zh/guide/lesson-14-ssl-traffic-monitor' },
                { text: 'Lesson 15: 进程命令监控', link: '/zh/guide/lesson-15-exec-command-monitor' },
                { text: 'Lesson 16: Bash 命令监控', link: '/zh/guide/lesson-16-bash-readline-monitor' }
              ]
            }
          ]
        },
        outlineTitle: '本页目录',
        lastUpdatedText: '最后更新',
        docFooter: {
          prev: '上一篇',
          next: '下一篇'
        }
      }
    }
  },

  themeConfig: {
    // 搜索
    search: {
      provider: 'local',
      options: {
        locales: {
          zh: {
            translations: {
              button: {
                buttonText: '搜索文档',
                buttonAriaLabel: '搜索文档'
              },
              modal: {
                noResultsText: '无法找到相关结果',
                resetButtonTitle: '清除查询条件',
                footer: {
                  selectText: '选择',
                  navigateText: '切换'
                }
              }
            }
          }
        }
      }
    },

    // 社交链接
    socialLinks: [
      { icon: 'github', link: 'https://github.com/haolipeng/ebpf-tutorial' }
    ],

    // 页脚
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024-present haolipeng'
    },

    // 编辑链接
    editLink: {
      pattern: 'https://github.com/haolipeng/ebpf-tutorial/edit/master/docs/:path',
      text: 'Edit this page on GitHub'
    }
  }
})
