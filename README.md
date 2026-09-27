# CloudDrive 多用户网盘

零依赖 Node.js 网盘：注册登录、个人文件空间、分享链接+密码。

## 本地运行

```bash
node server.js
# 打开 http://localhost:3000
```

## 部署到 Render（免费，24小时在线）

1. 注册 https://render.com （GitHub 登录）
2. 把这个项目推到一个新的 GitHub 仓库
3. Render 点 New → Web Service → 选你的仓库
4. 设置：
   - Runtime: Node
   - Build Command: 留空
   - Start Command: `node server.js`
   - Instance Type: Free
5. 点 Deploy，等 1 分钟上线

## 部署到 Koyeb（免费，不休眠）

1. 注册 https://koyeb.com
2. Create Service → GitHub → 选仓库
3. Builder: Node.js
4. Run command: `node server.js`
5. Instance: Free (eco)

## 功能

- 用户注册/登录（密码 scrypt 哈希）
- 每人独立文件空间，互不可见
- 上传/下载/删除文件
- 创建分享链接，可设分享密码
- 未登录只能通过分享链接+密码访问
- 传输面板实时显示上传下载进度和速度

## 注意

免费版 Render/Koyeb 重启后文件会清空（临时文件系统），适合临时分享使用。
