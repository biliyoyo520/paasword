# 🔐 Password Master v0.9.1

简体中文 | [English below](#english-version)

## 📚 目录索引

- [项目简介](#项目简介)
- [核心功能](#核心功能)
- [使用方法](#使用方法)
- [注意事项](#注意事项)

---

## 项目简介

Password Master 是一个基于实体密钥签名的密码生成器。用户输入任意内容后，工具会使用 GPG 私钥进行签名，并将签名结果用于派生高强度密码。每次输入都会生成唯一结果，确保安全性与不可预测性。

支持时间伪造功能，可设置未来或过去时间（但不得早于密钥创建时间），用于生成具有时间隔离性的密码，适合长期备份、阶段性访问控制等场景。

## ✨ 核心功能

- 🔑 使用 GPG 私钥签名用户输入，确保密码来源可信  
- 🧠 每次输入都生成不同密码，防止重复与预测  
- 🕒 支持时间伪造（faketime），可生成未来或过去密码  
- 📦 自动渲染终端框体，支持中英文混排对齐  
- 📤 可选纯文本输出，适用于脚本或自动化流程  
- 📊 时间差异报告，辅助验证伪造行为与时间一致性  

## 🚀 使用方法

```bash
python password.py
```

## 📌 注意事项

- 密码生成依赖 GPG 私钥，请确保密钥已导入并可用  
- faketime 不得早于密钥创建时间，否则验证失败  
- 推荐使用 UTF-8 编码终端环境运行  
- 请复制完整的一整行密码，避免截断或误取  
- 密码不包含易混淆字符，可以在可信设备获取密码后输入  

---

## English Version

### 📚 Index

- [Overview](#overview)
- [Features](#features)
- [Usage](#usage)
- [Notes](#notes)

---

### Overview

Password Master is a password generator powered by physical GPG key signatures. It signs any user input using your private key, then derives a high-strength password from the signature. Every input produces a unique result, ensuring security and unpredictability.

It supports time forgery, allowing you to simulate future or past timestamps (as long as they’re not earlier than the key creation time). This enables time-isolated password generation, ideal for long-term backups or staged access control.

### ✨ Features

- 🔑 Signs user input with GPG private key for trusted password derivation  
- 🧠 Unique output for every input, preventing reuse and prediction  
- 🕒 Supports faketime to simulate future or past password generation  
- 📦 Auto-rendered terminal boxes with proper alignment for mixed CJK/ASCII  
- 📤 Optional plain output for scripting and automation  
- 📊 Time drift report to verify forgery and timestamp consistency  

### 🚀 Usage

```bash
python password.py
```

### 📌 Notes

- Password generation requires a valid GPG private key  
- faketime must not be earlier than the key creation time  
- UTF-8 terminal environment is recommended  
- Always copy the full password line to avoid truncation  
- Passwords avoid ambiguous characters and are safe for manual input on trusted devices  

---