# TMR Node (Triple Modular Redundancy)

基於 UDP 廣播與 C++ 多執行緒實作的分散式多數決節點程式。本系統支援多任務並發處理、AES 加密運算、錯誤注入測試，以及基於 3000ms 超時機制的 3TMR / 2MR 容錯降級投票。

## 1. 系統架構與全域狀態

本程式以多執行緒架構運行，主要分為三個核心執行緒：

* **Main Thread**: 負責讀取使用者輸入、發起任務 (`TASK`) 與切換錯誤注入狀態 (`fault`)。
* **Listener Thread**: 背景監聽 UDP Port `8888`，處理收到的 `TASK` 與 `RESULT` 封包。
* **Worker Thread (`process_task`)**: 每個任務獨立開啟的執行緒，負責 AES 加密、等待同步與執行投票。

### 核心資料結構

系統使用全域 `std::map<string, TaskState> tasks` 來管理多個並發任務。

```cpp
struct TaskState {
    string plaintext;                  // 原始測資
    string my_result;                  // 本機運算出的 AES Cipher
    map<string, string> peer_results;  // 儲存其他節點回傳的結果 (Key: 節點ID, Value: Cipher)
    bool finished = false;             // 任務結算標記
    condition_variable cv;             // 用於觸發/等待該任務結果的條件變數
};
```

所有對 `tasks` 的讀寫操作皆受全域互斥鎖 `std::mutex mtx` 保護。

---

## 2. 核心運作流程

### 任務發起 (Task Initiation)
1. 使用者在終端機輸入字串。
2. 呼叫 `gen_task_id()` 透過系統時間戳生成唯一 Task ID。
3. 鎖定 `mtx`，在 `tasks` 中初始化該 Task ID 的狀態，並寫入 `plaintext`。
4. 呼叫 `broadcast()` 透過 UDP 發送 `TASK:<task_id>:<plaintext>` 給 `peer_ips` 列表中的節點。
5. 建立並分離 (`detach`) 一個新的 `process_task` 執行緒處理該任務。

### 任務處理與同步 (Processing & Synchronization)
`process_task` 函式的具體執行步驟：

1. **運算**：呼叫 `compute_aes` 進行 AES-256-CBC 加密。若 `inject_fault` (`atomic bool`) 為 `true`，則在密文後方加上 `_WRONG` 字串。
2. **儲存與廣播**：鎖定 `mtx`，將結果存入 `tasks[task_id].my_result`，接著廣播 `RESULT:<task_id>:<my_id>:<cipher>`。
3. **阻塞等待 (Timeout Mechanism)**：使用 `unique_lock` 配合 `cv.wait_for`。執行緒會在此休眠，直到以下兩種情況之一發生：
    * **條件滿足**：`peer_results.size() >= peer_ips.size()`（收齊其他所有節點的結果）。
    * **超時觸發**：達到設定的 3000ms 上限。
4. **解鎖與投票**：等待結束後，釋放 `unique_lock`（避免與 `vote` 內的鎖死結），然後呼叫 `vote(task_id)`。
5. **結案**：標記 `finished = true`。

### 網路監聽與喚醒 (Listener & Notification)
`listener_thread` 負責解析 UDP 封包：

* **收到 TASK**：解析出 `task_id` 與 `text`，鎖定 `mtx` 建立任務狀態，並啟動 `process_task` 執行緒。
* **收到 RESULT**：解析出 `task_id`、`node_id` 與 `cipher`。鎖定 `mtx` 將結果寫入 `tasks[task_id].peer_results[node_id]`。寫入完成後，呼叫 `tasks[task_id].cv.notify_one()` 喚醒正在等待該任務的 `process_task` 執行緒。

---

## 3. 投票與容錯機制 (Voting Logic)

`vote()` 函式負責結算任務。它會統計本機結果 (`my_result`) 與所有收到的 Peer 結果 (`peer_results`)，計算最高相同票數 (`max_count`)，並依據總投票人數 (`total_voters`) 進行決策：

* **總人數 = 3 (3TMR 標準模式)**：
    * `max_count >= 2`：成功 (允許 1 個節點錯誤或發生 Byzantine Fault)。
    * `max_count < 2`：失敗 (三方結果皆不同)。
* **總人數 = 2 (2MR 降級模式)**：
    * 當某節點斷線或網路延遲超過 3000ms，系統自動降級為 2MR。
    * `max_count == 2`：成功 (雙方結果必須完全一致)。
    * `max_count < 2`：失敗 (雙方分歧，無法信任)。
* **總人數 < 2**：
    * 資料不足，無法進行交叉驗證。

---

## 4. 執行與操作

本程式需要傳入節點 ID 以進行身分識別並載入對應的叢集 IP 配置。

### 啟動節點
在終端機執行編譯後的程式，並傳入節點編號 (A, B 或 C)：
```bash
./TMR-Pi A

### 操作指令 
* **輸入 `fault`**：切換錯誤注入模式 (ON/OFF)。
* **輸入任意字串**：發起一般加密與投票任務。