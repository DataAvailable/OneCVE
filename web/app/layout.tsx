import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "OneCVE 本地漏洞检测工作台",
  description: "从 C/C++ 源码构建 LLVM Bitcode，并执行一键漏洞扫描。",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
