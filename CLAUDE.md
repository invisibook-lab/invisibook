# CLAUDE.md

## 项目结构
- chain： Invisibook的L2链代码，用yu来实现完成
- app: Invisibook 的 desktop app，用rust以及 dioxus 框架实现
- lib：Invisibook的 rust公用库，里面装着一些app和cli共用的rust业务逻辑
- cli: Invisibook的交互命令行，用rust实现

## 各组件详述
### chain  
链需要用yu这个框架来开发，链上有2个tripod：
1. OrderBook tripod：
   - SendOrder：接受客户端发来的writing请求，把订单存入链上，并且进行撮合订单逻辑，把撮合的结果更新在链上
   - SettleOrder：接受客户端发来的writing请求，先检查结算的订单是否是之前撮合成功的，检查通过之后再验证zk proof（暂无实现，用todo表示就行），
   验证通过之后 对订单进行结算，更新订单状态和账户状态
   - QueryOrders：接受客户端发来的reading请求，根据条件查询订单，查询的时候有分页功能（需要limit和offset）
2. Account tripod：
   - GetAccount：接受客户端发来的reading请求，根据传入的 公钥地址 来查看账户详情
   - Deposit：接受客户端发来的writing请求，验证发上来的zk proof（todo），此处需要验证的是用户在其他链的invisibook桥合约里有存入相应数量的资产，
   验证通过之后，创建对应的账户余额的账户
   - Withdraw：接受客户端发来的writing请求，验证发上来的zk proof，此处需要验证的是用户要提现的金额必须小于等于当前余额（todo）。
配置文件装在单独的文件夹cfg里，用toml格式。
### app
desktop 和 mobile两个包，各自表示桌面应用和手机端应用，它们各自专属的布局适配，ui里用来放 dioxus组件，尽量复用。
### cli

### lib
- 客户端公用的链调用：包括从客户端发送请求到chain的逻辑，要求使用https://github.com/yu-org/yu-sdk的rust库，封装发送订单、结算订单、查看订单的代码逻辑
- 点对点通信：
- 多方安全计算：

## CI
使用github action来实现CI，