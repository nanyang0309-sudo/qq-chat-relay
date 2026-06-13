# QQ_chat Relay Server

跨互联网聊天应用中继服务器，部署到 Render 免费版。

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

## 一键部署（推荐）

点击上方按钮 → 登录 Render → 点 Deploy，搞定。

## 手动部署

1. 在 [render.com](https://render.com) 注册免费账号
2. 创建 **Web Service**，连接本仓库
3. **Start Command** 填：python relay_server.py
4. 选 **Free** 套餐 → **Create Web Service**

部署完成后会得到一个 https://qq-chat-relay.onrender.com 地址。

## 客户端连接

客户端（QQChatClient.exe）填写：
- 服务器地址：qq-chat-relay.onrender.com
- 端口：9876

## 注意

纯 Python 内置模块实现，**零外部依赖**。
