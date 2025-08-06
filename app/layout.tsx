import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { ThemeProvider } from '@/components/theme-provider'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: '天眼网络监控系统',
  description: '实时网络监控和威胁检测系统',
  keywords: ['网络监控', '威胁检测', '系统监控', '安全监控'],
  authors: [{ name: '网络监控团队' }],
  viewport: 'width=device-width, initial-scale=1',
    generator: 'v0.dev'
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="zh-CN" suppressHydrationWarning>
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="description" content="天眼网络监控系统 - 实时网络监控和威胁检测" />
        <meta name="keywords" content="网络监控,威胁检测,系统监控,安全监控" />
        <meta name="author" content="网络监控团队" />
        <link rel="icon" href="/favicon.ico" />
        <title>天眼网络监控系统</title>
      </head>
      <body className={inter.className} suppressHydrationWarning>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <div className="min-h-screen bg-background">
            <main className="container mx-auto px-4 py-6">
              {children}
            </main>
          </div>
        </ThemeProvider>
      </body>
    </html>
  )
}
