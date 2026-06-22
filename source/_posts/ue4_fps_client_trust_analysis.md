---
title: UE4 FPS 手游客户端信任边界安全分析——移动、弹道与反外挂系统
date: 2026-06-03 15:00:00
tags:
  - UE4
  - FPS
  - 游戏安全
  - 逆向工程
  - 反外挂
  - 客户端安全
  - Unreal
categories:
  - 安全分析
description: 对某款 UE4 移动端 FPS 游戏进行逆向分析，梳理客户端-服务端信任边界问题，覆盖移动系统、弹道系统、反外挂系统三大攻击面，识别 40+ 个校验弱点并提出安全加固建议。
---

## 摘要

本文基于对某款 UE4 移动端 FPS 游戏的逆向分析，系统梳理了客户端-服务端架构中的信任边界问题。分析覆盖三大攻击面：**移动系统**（速度与重力校验绕过）、**弹道系统**（射击方向与命中数据篡改）、**反外挂系统**（检测机制的盲区与开关控制）。共识别出 40+ 个可利用的校验弱点，并按风险等级分类。文章最后提出分层的安全加固建议。

> 本文所有地址、偏移、寄存器细节均已脱敏，仅保留概念层面的分析结论。

---

## 一、分析范围概览

分析基于 `libUE4.so`（ARM64 架构）的静态逆向与 IDA Pro 反编译，覆盖以下模块：

| 模块 | 分析函数数 | 核心组件 |
|---|---|---|
| 武器反外挂 | 11 | WeaponAntiCheatLogicObject, CheatManager, ShootWeapon |
| 移动系统 | ~220+ | MovementComponent, CharacterMovement, AttributeSystem |
| 弹道/射击 | ~180+ | ShootWeapon, BulletManager, WeaponEventProxy |

---

## 二、反外挂系统架构分析

### 2.1 整体设计

游戏的反外挂系统以**武器系统为核心**，包含 6 个主要类：

```
FAntiCheatSetting
  └── GetAllSwitchNames() → 可用开关列表

FGNGameCheatManager (作弊管理/调试)
  ├── SetAntiCheatSwitch() → 通过属性偏移直接写入开关值
  └── SwitchWeaponAntiCheat() → 切换武器反外挂状态

FWeaponAntiCheatLogicObject (核心逻辑)
  ├── GetShootPlayerShootDirAndDist() → 射击方向 + 距离验证
  ├── GetSafetyScoreLastTime() / SetSafetyScoreLastTime() → 信用评分时间戳
  ├── EnterSafetyScore() → 记录安全事件（29 种信用策略类型）
  └── ClearPlayerPosRecordInfo() → 重置玩家位置记录

FGngameCommonWeaponAS (武器能力系统)
  └── K2_SetAntiCheatOn_Runtime() → 运行时 bit 标志开关

FShootWeapon
  └── NotifyReloadToAntiCheat() → 装弹事件通知

FGrapplingHookMovement
  └── CanDoExtraLaunchForAntiCheat() → 抓钩弹射验证
```

### 2.2 关键发现：反外挂开关机制

反外挂的运行时开关位于武器能力系统的一个标志位字段中（`bit 5`，值 `0x20`）。切换逻辑非常简单：

```c
if (enable)
    flags |= 0x20;   // 开启
else
    flags &= ~0x20;  // 关闭
```

这意味着：
- 反外挂状态是**运行时可切换**的，不是编译期固定
- 标志位存储在某武器组件对象的偏移位置，可通过内存写入修改
- 存在 `SetAntiCheatSwitch(FName, bool)` 函数，可通过属性名称字符串来控制任意反外挂开关

### 2.3 关键发现：反外挂的武器依赖盲区

所有 11 个反外挂函数都围绕**武器系统**运行。没有独立的 Pawn/MovementComponent 级别的移动反外挂检测。当角色未装备武器时，武器能力系统对象不存在，其反外挂标志位也不存在——这意味着在无武器状态下，速度/重力修改可能完全不被武器反外挂系统检测。

### 2.4 信用评分系统（ECreditTactics）

`EnterSafetyScore` 函数接收一个包含 29 种信用策略类型的枚举，每种类型对应一个独立的时间戳字段。这本质是一个**事件驱动的行为审计系统**——每次可疑行为被记录时，系统记录该行为类型和发生时间，后续可用于离线分析或实时阈值判断。但从现有分析看，这些时间戳更多用于**事后审计**而非**实时阻断**。

### 2.5 射击验证机制

`GetShootPlayerShootDirAndDist` 是射击方向验证的核心函数：
1. 反序列化客户端上报的 264 字节 `BulletHitInfoUploadData`
2. 从中提取命中位置、射击方向、目标实体 ID、命中类型等信息
3. 通过实体 ID 在服务端全局哈希表中查找目标对象
4. 计算从射击者到目标的实际方向向量和 3D 欧几里得距离
5. 将计算结果与客户端上报数据进行比对

---

## 三、移动系统绕过分析

### 3.1 速度修改绕过

#### [严重] LimitVelocity 绕过 — MaxSpeed 膨胀

`LimitVelocity` 是速度钳制的核心函数，其逻辑为：

```c
float maxSpeed = GetMaxSpeed();  // 虚函数调用
if (sqMag > maxSpeed * maxSpeed) {
    float scale = maxSpeed / sqrtf(sqMag);
    velocity *= scale;  // 等比缩放至合法范围
}
```

如果 `GetMaxSpeed()` 返回一个极大值，则 `sqMag > maxSpeed²` 条件永不满足，速度限制完全失效。`GetMaxSpeed()` 是虚函数，可通过 vtable hook 修改返回值。绕过路径：
- 修改属性系统的 `OnRep_MaxWalkSpeedLimit` 复制值
- Hook `K2_GetModifiedMaxSpeed` 虚函数
- 修改速度倍率 `SpeedScale` 属性

#### [严重] ServerMove 旧版接口 — 弱验证路径

游戏存在多个 ServerMove RPC 变体：

| 接口 | 参数 | 验证强度 |
|---|---|---|
| `GnyxServerMove` | MoveData + ExtraPacket | 完整验证 |
| `GnyxServerMoveOld` | 仅 MoveData | **缺少 ExtraPacket** |
| `GnyxServerMoveDual` | PendingData + MoveData + ExtraPacket | 完整验证 |
| `ServerAppendMove` | AppendData + MoveData | 部分验证 |

`GnyxServerMoveOld` 不接收 `ExtraPacket`（可能包含校验和、时间戳校验等附加验证数据），是一个潜在的弱验证入口。如果该旧接口未被废弃，攻击者可通过它提交被篡改的移动数据。

#### [严重] SyncLaunch — 直接速度注入

`SyncLaunch` 函数允许直接设置角色速度，支持分别覆盖 XY 和 Z 分量（通过 `bXYOverride`/`bZOverride` 标志）。如果服务端不验证传入速度值与角色当前最大速度、移动模式的关系，则可以提交任意速度值，绕过所有基于 `CalcVelocity`/`LimitVelocity` 的限速。

#### [高] 速度倍率堆叠

角色基类中存在多个速度倍率 getter：`SpeedScale`、`MaxWalkSpeedLimit`、`KnockdownSpeedScale`、`MeleeAttackBeatSpeedScale`、`ReloadSpeedScale` 等。如果这些倍率在服务端验证之后才应用到最终速度，修改任一倍率值即可影响最终移动速度。多个倍率的乘积堆叠可能产生远超预期的速度值。

#### [高] CalcVelocity 参数操控

`CalcVelocity` 接收 `DeltaTime`、`Friction`、`BrakingDeceleration` 等参数来影响速度衰减。如果客户端可以通过 RPC 提交这些参数，则可以减少摩擦力使速度衰减变慢，或减少制动力延长减速时间。

#### [高] 客户端位置修正抑制

服务端通过 `ClientAdjustPosition` 将计算出的正确位置发送给客户端。如果客户端 Hook 此函数忽略修正，客户端和服务端位置将逐渐漂移。攻击者可以保持在修正触发的偏差阈值以下，实现"温水煮青蛙"式的速度作弊。

#### [中] ServerMove 精度间隙

标准 ServerMove 使用 `FVector_NetQuantize10`（加速度）和 `FVector_NetQuantize100`（位置）进行量化传输。量化精度损失可能造成可利用的间隙——数值在量化后可能"看起来"在合法范围内，但实际值略高。

#### [中] 移动模式切换绕过

不同移动模式（Walking/Falling/Flying/Swimming/Custom）有不同的速度上限和重力行为。通过 `SetMovementMode` 切换到 Flying 模式可完全绕过重力和地面速度限制。如果服务端不验证模式切换的合法性，攻击者可提交伪造的模式切换请求。

### 3.2 重力修改绕过

#### [严重] GetGravityZ 虚函数 Hook

`GetGravityZ()` 通过虚函数调用获取当前重力值。Hook 此虚函数返回 0.0 或极小值即可实现零重力/低重力效果，影响所有依赖重力计算的移动逻辑。

#### [严重] ClientCheatFly / ClientCheatWalk

引擎内置的作弊飞行函数。如果这些函数可通过 RPC 或控制台命令在非调试环境下触发，即可直接进入无重力飞行模式。

#### [高] VoidMover 重力状态切换

存在一个 `VoidMover::SetGravityState` 函数，可开关指定角色的重力状态。这可能是技能驱动（如虚空移动），但如果可被非法调用，则提供了另一个重力绕过路径。

#### [高] WorldGravityZ 复制

世界重力是一个复制属性，客户端的 `OnRep_WorldGravityZ` 在收到服务端更新时触发。如果本地 WorldSettings 对象可被修改，客户端侧的重力计算将与服务端不一致。

### 3.3 综合移动绕过场景

**全速绕过链**：
```
修改 MaxWalkSpeedLimit → 极大值
  → 调用 GnyxServerMoveOld（绕过 ExtraPacket 验证）
  → LimitVelocity 不触发 → 服务端接受超速数据
```

**重力消除链**：
```
Hook GetGravityZ 虚函数 → 返回 0.0
  或 ClientCheatFly（如可访问）
  或 SetMovementMode → MOVE_Flying
  → 无重力，自由 3D 移动
```

**武器避检链**：
```
不装备武器（武器能力系统不存在）
  → MovementComponent 级别修改速度/重力
  → 绕过所有武器反外挂函数
  （注：服务端 ServerMove 验证仍可能捕获）
```

---

## 四、弹道系统绕过分析

### 4.1 射击管线总览

```
客户端:                                    服务端:
                                
按键开火
  ↓
FireWeaponStateLogic::HandleToFire()
  ↓
HandleFireShoot()
  ↓
ComputeAimDirection()  ← 相机/控制器旋转 → FVector 方向
  ↓
GetMuzzleTransform()   ← 从武器组件读取枪口 FTransform
  ↓
★ ShootBullet_Internal  ← 【核心】弹道组装
  │  ① 欧拉角(Pitch/Yaw/Roll) → 四元数(FQuat)
  │  ② FTransform{Rotation=quat, Translation=位置}
  │  ③ 根据子弹类型分派模拟路径(A/B/C)
  │  ④ End-Start → 方向向量 → 最终发射
  ↓
LaunchSimulateBullet(Start, End)
  ↓
生成 BulletHitInfoUploadData
  ↓                                    → SendSimulateBulletToServer()
  ↓                                    → ServerHandleHitDataArray()
OperateHitDataPreUpload()
  ↓
Flush() → 上传命中数据
```

### 4.2 ShootBullet_Internal — 弹道方向控制核心

`ShootBullet_Internal` 是射击管线中连接枪口变换和子弹模拟的**关键中间层**。其核心机制为：

**参数语义**：
- 参数 1-3：枪口世界坐标 (StartLocation.X/Y/Z)
- 参数 4-6：发射欧拉角 (Pitch/Yaw/Roll)
- 参数 7-8：子弹终点 (ShootEnd)

**内部流程**：
1. 将欧拉角 (Pitch/Yaw/Roll) 转换为四元数 (FQuat)
2. 用四元数 + 位置构建完整 FTransform
3. 根据子弹类型分派到三种不同的模拟路径
4. 计算方向向量：`(End - Start).Normalized()`
5. 调用最终发射函数

**攻击面**：
- 参数 4-5 (Pitch/Yaw) 是裸 float 值，直接控制弹道俯仰角和偏航角
- 修改 2 个 float 即可重定向所有子弹
- 无需理解 FTransform/FQuat 内存布局
- 三个弹道模拟分支提供了多层次的拦截点

### 4.3 弹道绕过攻击向量

#### [严重] 命中数据预上传修改

客户端在射击后生成 `BulletHitInfoUploadData`（264 字节），包含击中位置、方向、目标实体 ID 等。`OperateHitDataPreUpload` 在上传前对数据进行最后处理。如果服务端 `ServerHandleHitDataArray` 不重新执行完整的射线追踪来验证命中，仅信任客户端提交的数据，攻击者可以：
- Hook `OperateHitDataPreUpload` 修改目标位置/实体
- Hook `PreUploadLineHitData` 将未命中改为命中
- 直接构造并提交虚假的命中数据数组

#### [严重] 弹道模拟数据篡改

`LaunchSimulateBullet(Start, End)` 的 Start 和 End 参数直接定义子弹轨迹。攻击者可以：
- 设置 `End = 敌方头部位置` → 子弹总是命中头部
- 设置 `End = Start + AimDirection * Range` → 伪造弹道

`SendSimulateBulletToServer` 将模拟结果数组发送给服务端，可直接修改该数组。

#### [严重] 枪口变换修改

`GetMuzzleTransform` 返回枪口的 FTransform（位置+旋转）。Hook 此函数可以：
- 修改旋转分量 → 子弹朝任意方向发射
- 修改位置分量 → 子弹从任意位置射出
- 修改枪口 Socket 的 RelativeRotation → 所有子弹方向系统性偏转

#### [高] 后坐力/散布消除

游戏提供了多个后坐力/散布控制函数，可利用实现完美精准：
- `GMClearAllRecoilSet` → 清除所有后坐力
- `K2_SetStabilizerRecoilFactorX/Y` → 稳定器归零
- `OnRep_SpreadScale` → 散布倍率为 0
- 效果：所有子弹沿完美直线飞行，无任何偏移

#### [高] 子弹物理参数操纵

可修改子弹的物理行为以增强命中：
- `BulletGravityFactor = 0` → 无重力下坠
- `BulletSpeedFactor = 极大值` → 瞬间命中
- `BulletRadiusFactor = 极大值` → 增大碰撞体积
- `TraceChannel` 修改 → 子弹可穿透墙壁

#### [高] 霰弹聚拢

- `ShotgunBallisticScale = 0` → 所有弹丸无散布
- `SingleShootPelletNum` 增大 → 更多弹丸
- 效果：所有弹丸聚拢为一点，等效多倍伤害

### 4.4 综合弹道绕过场景

**全弹道控制链**：
```
Hook GetMuzzleTransform → 修改枪口方向指向目标
  → Hook ShootBullet_Internal → 修改 Pitch/Yaw 参数
  → Hook LaunchSimulateBullet → 设置 End = 目标位置
  → Hook PreUploadLineHitData → 确保命中数据一致
  → 服务端收到伪造数据但不重做射线追踪 → 弹道完全被客户端控制
```

**精准无后坐力链**：
```
GMClearAllRecoilSet + StabilizerRecoilFactor 归零 + SpreadScale 归零
  → 所有子弹沿完美直线飞行
```

**穿墙弹道链**：
```
TraceChannel 修改 + BulletRadiusFactor 增大 + GravityFactor = 0
  + ResumeMoveAfterImpactWithNoLost
  → 子弹穿透所有障碍物命中目标
```

---

## 五、信任边界总结

### 5.1 客户端信任过度的问题

综合分析揭示了该游戏架构中一个系统性的安全问题：**服务端对客户端提交的数据验证不完整**。

| 系统 | 客户端可操控的数据 | 服务端验证状态 |
|---|---|---|
| 移动 | 速度、位置、加速度、移动模式 | 依赖 ServerMove 内嵌验证，存在旧版弱接口 |
| 弹道 | 射击方向、命中位置、命中目标、弹道终点 | 仅验证武器实例 ID 和子弹消耗，未重复射线追踪 |
| 反外挂 | 信用评分时间戳、反外挂开关标志 | 开关可被内存写入修改 |
| 属性 | MaxSpeed、SpeedScale、GravityZ 等 | OnRep 在客户端即时生效，存在预测窗口 |

### 5.2 核心信任假设（被分析打破的）

1. **"客户端 GunMuzzle Transform 是可信的"** — 实际上可被 Hook 任意修改
2. **"客户端 BulletHitInfoUploadData 是真实射击结果"** — 实际上可通过多层拦截构造
3. **"GetMaxSpeed 返回值受服务端控制"** — 实际上虚函数可被 Hook
4. **"反外挂标志位不可被客户端修改"** — 实际上位于可写的内存区域
5. **"旧版 ServerMove 接口不会被利用"** — 实际上如果接口未废弃，就是弱验证入口

### 5.3 攻击复杂度分级

| 攻击类型 | 技术门槛 | 需要绕过 | 效果 |
|---|---|---|---|
| Pitch/Yaw 修改 | 低（2 个 float 修改） | 无 | 弹道完全重定向 |
| MaxSpeed 膨胀 | 低（vtable hook） | ServerMove 验证 | 速度限制失效 |
| 命中数据伪造 | 中（需理解数据结构） | 服务端命中验证 | 任意目标命中 |
| 后坐力消除 | 低（调用现有接口） | 无 | 完美精准度 |
| 反外挂关闭 | 低（内存写入 bit 位） | 无 | 检测系统失效 |

---

## 六、安全加固建议

### 6.1 服务端验证增强

1. **服务端重做射线追踪**：收到命中数据后，使用服务端权威的枪口位置和目标位置重新执行射线追踪，验证路径上无阻挡、目标在有效射程内

2. **服务端速度重算**：收到 ServerMove 后重新调用 `LimitVelocity` + `CalcVelocity`，不信任客户端提交的最终速度

3. **弹道参数校验**：验证射击的 Pitch/Yaw 参数与角色当前相机/控制器的瞄准方向一致

4. **多弹丸/霰弹独立计算**：霰弹等武器的弹丸散布应在服务端独立计算

### 6.2 接口与配置加固

5. **废弃旧版接口**：如果 `GnyxServerMoveOld` 验证较弱，应统一验证逻辑或废弃

6. **MaxSpeed 硬上限**：定义 `constexpr` 硬上限，`GetMaxSpeed` 返回值不应超过该值

7. **倍率乘积上限**：所有速度倍率属性应有合理的乘积上限，防止堆叠溢出

8. **TraceChannel 保护**：射线追踪通道不应由客户端属性控制

9. **BulletRadius/BulletGravity 上限**：子弹物理参数应有合理的最大值限制

### 6.3 反外挂体系加固

10. **非武器态独立检测**：移动反外挂不应仅依赖武器系统，应在 Pawn/MovementComponent 级别独立运行

11. **反外挂开关保护**：运行时标志位应受到完整性保护，防止内存写入修改

12. **ClientAdjust 强制执行**：服务端应验证客户端是否应用了位置修正

13. **遥测实时化**：审计数据应触发实时告警而非仅离线分析

14. **SyncLaunch 限速**：`SyncLaunch` 的传入速度应验证不超过角色当前允许的最大速度

15. **移动模式切换验证**：服务端应验证客户端是否有权限切换到请求的移动模式

---

## 七、结语

本文通过对 UE4 FPS 手游客户端二进制文件的系统性逆向分析，揭示了客户端-服务端架构中的信任边界薄弱点。核心发现是：**游戏在移动系统、弹道系统和反外挂系统三个层面均存在客户端数据被过度信任的问题**，且反外挂系统过度依赖武器系统而缺乏独立的 Pawn 级别检测。

最关键的单一攻击向量是 **ShootBullet_Internal 的 Pitch/Yaw 参数修改**——仅修改 2 个 float 值即可实现弹道完全重定向，且所有下游数据（End 位置、命中数据）自动与新方向保持一致，使得服务端难以区分合法与伪造数据。

这些发现表明，客户端-服务端架构的安全设计需要遵循 **"Never Trust the Client"** 原则——服务端必须独立验证所有影响游戏公平性的关键数据，包括但不限于：移动速度、子弹轨迹、命中检测和后坐力计算。
