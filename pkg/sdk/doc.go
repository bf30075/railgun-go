// Package sdk 是用于组装 railgun-go 引擎会话的公开框架层。
//
// 该 package 将应用编排留在底层 Railgun primitive 之外。调用方提供 store、钱包材料、
// 网络配置、provider、proof 配置和可选同步策略；Runtime 暴露稳定 facade，用于同步、
// 余额、POI 操作、发送交易，以及私有 shield/unshield 工作流。
package sdk
