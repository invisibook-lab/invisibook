# CLAUDE.md

## 项目结构
- chain： Invisibook的L2链代码，用yu来实现完成
- app: Invisibook 的 desktop app，用rust以及 dioxus 框架实现
- lib：Invisibook的 rust公用库，里面装着一些app和cli共用的rust业务逻辑
- cli: Invisibook的交互命令行，用rust实现

## 各组件详述
### chain

### app
desktop 和 mobile两个包，各自表示桌面应用和手机端应用，它们各自专属的布局适配，ui里用来放 dioxus组件，尽量复用。
### cli

### lib
- 客户端公用的链调用：包括从客户端发送请求到chain的逻辑，要求使用yu-sdk的rust库，封装发送订单、结算订单、查看订单的代码逻辑
- 点对点通信：
- 多方安全计算：