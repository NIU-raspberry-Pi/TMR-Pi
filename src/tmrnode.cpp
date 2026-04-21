#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <atomic>

using namespace std;

#define PORT 8888

// ================= 全域 =================
string my_id;
vector<string> peer_ips;
atomic<bool> inject_fault(false);

// ================= Task State =================
struct TaskState {
    string plaintext;
    string my_result;
    map<string, string> peer_results;
    bool finished = false;
    condition_variable cv;
};

map<string, TaskState> tasks;
mutex mtx;

// ================= 工具 =================
string gen_task_id() {
    return to_string(chrono::steady_clock::now().time_since_epoch().count());
}

// ================= AES =================
string compute_aes(const string& plaintext) {
    unsigned char key[32] = {
        '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5',
        '6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1'
    };

    unsigned char iv[16] = {
        '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'
    };

    unsigned char ciphertext[128];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len,
        (unsigned char*)plaintext.c_str(), plaintext.length());

    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    char hex_str[256] = {0};
    for (int i = 0; i < ciphertext_len; i++) {
        sprintf(hex_str + (i * 2), "%02x", ciphertext[i]);
    }

    return string(hex_str);
}

// ================= UDP =================
void broadcast(const string& msg) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    for (auto &ip : peer_ips) {
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        sendto(sockfd, msg.c_str(), msg.length(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
    }

    close(sockfd);
}

// ================= Vote =================
void vote(const string& task_id) {
    lock_guard<mutex> lock(mtx);
    auto &task = tasks[task_id];

    map<string, int> counter;

    counter[task.my_result]++;
    for (auto &p : task.peer_results) {
        counter[p.second]++;
    }

    string winner;
    int max_count = 0;

    for (auto &c : counter) {
        if (c.second > max_count) {
            max_count = c.second;
            winner = c.first;
        }
    }

    int total_voters = 1 + task.peer_results.size();

    cout << "\n=== Task " << task_id << " 投票結果 ===\n";

    if (total_voters == 3) {
        if (max_count >= 2)
            cout << "[成功] 3TMR 多數決 (" << max_count << "/3)\n";
        else
            cout << "[失敗] 3TMR 無法達成一致\n";
    }
    else if (total_voters == 2) {
        if (max_count == 2)
            cout << "[成功] 2MR 一致\n";
        else
            cout << "[失敗] 2MR 分歧\n";
    }
    else {
        cout << "[錯誤] 資料不足\n";
    }

    cout << "===========================\n> ";
    fflush(stdout);
}

// ================= Task Processing =================
void process_task(const string& task_id, const string& plaintext) {
    // 1. 開始運算提示
    cout << "\n[任務啟動] ID: " << task_id << " | 內容: " << plaintext << endl;

    string my_cipher = compute_aes(plaintext);

    if (inject_fault.load()) {
        my_cipher += "_WRONG";
        cout << "[警告] ID: " << task_id << " 注入錯誤結果" << endl;
    }

    {
        lock_guard<mutex> lock(mtx);
        tasks[task_id].my_result = my_cipher;
    }

    // 2. 廣播提示
    broadcast("RESULT:" + task_id + ":" + my_id + ":" + my_cipher);
    cout << "[廣播] ID: " << task_id << " 結果已發送，等待 Peer..." << endl;

    unique_lock<mutex> lock(mtx);
    
    // 3. 等待過程的 UI 表現
    bool success = tasks[task_id].cv.wait_for(lock,
        chrono::milliseconds(3000),
        [&] {
            return tasks[task_id].peer_results.size() >= peer_ips.size();
        });

    if (!success) {
        cout << "[逾時] ID: " << task_id << " 未收齊所有結果，進行降級投票" << endl;
    } else {
        cout << "[收齊] ID: " << task_id << " 收到所有 Peer 結果" << endl;
    }

    // 注意：這裡必須先解鎖，因為 vote 內部也會上鎖
    lock.unlock(); 
    vote(task_id);

    lock.lock();
    tasks[task_id].finished = true;
}

// ================= Listener =================
void listener_thread() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr, cli;
    socklen_t len = sizeof(cli);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));

    char buffer[1024];

    while (true) {
        int n = recvfrom(sockfd, buffer, 1024, 0,
                         (struct sockaddr*)&cli, &len);

        buffer[n] = '\0';
        string msg(buffer);

        // ===== TASK =====
        if (msg.rfind("TASK:", 0) == 0) {

            size_t p1 = msg.find(':', 5);

            string task_id = msg.substr(5, p1 - 5);
            string text = msg.substr(p1 + 1);

            {
                lock_guard<mutex> lock(mtx);
                auto &t = tasks[task_id];
                t.plaintext = text;
            }

            thread(process_task, task_id, text).detach();
        }

        // ===== RESULT =====
        else if (msg.rfind("RESULT:", 0) == 0) {

            size_t p1 = msg.find(':', 7);
            size_t p2 = msg.find(':', p1 + 1);

            string task_id = msg.substr(7, p1 - 7);
            string node_id = msg.substr(p1 + 1, p2 - p1 - 1);
            string cipher = msg.substr(p2 + 1);

            {
                lock_guard<mutex> lock(mtx);
                tasks[task_id].peer_results[node_id] = cipher;
            }

            tasks[task_id].cv.notify_one();
        }
    }
}

// ================= Main =================
int main(int argc, char* argv[]) {

    map<string, string> cluster_ips = {
        {"A", "192.168.50.41"},
        {"B", "192.168.50.14"},
        {"C", "192.168.50.103"}
    };

    if (argc < 2) {
        cout << "用法: ./tmr_node A/B/C\n";
        return 1;
    }

    my_id = argv[1];

    for (auto &n : cluster_ips) {
        if (n.first != my_id)
            peer_ips.push_back(n.second);
    }

    cout << "啟動節點 " << my_id << endl;

    thread(listener_thread).detach();

    string input;

    while (true) {
        cout << "\n> ";
        getline(cin, input);

        if (input == "fault") {
			inject_fault.store(!inject_fault.load());
            cout << "fault: " << inject_fault.load() << endl;
        }
        else if (!input.empty()) {

            string task_id = gen_task_id();

            {
                lock_guard<mutex> lock(mtx);
                auto &t = tasks[task_id];
                t.plaintext = input;
            }

            broadcast("TASK:" + task_id + ":" + input);

            thread(process_task, task_id, input).detach();
        }
    }
}