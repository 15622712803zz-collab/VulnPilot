import os
import re
import time
import requests
import csv

# 替换为你的 Vulhub 本地仓库路径
VULHUB_DIR = r"D:\vulhub" 
# 替换为你的 NVD API Key (建议申请，否则限流极其严重)
NVD_API_KEY = "b9045636-5ebc-4832-91b4-38a6639c4971"  

def get_vulhub_cves(base_dir):
    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,})', re.IGNORECASE)
    targets = []
    
    for root, dirs, files in os.walk(base_dir):
        for dir_name in dirs:
            match = cve_pattern.search(dir_name)
            if match:
                # 提取应用名称，通常是上一级目录
                app_name = os.path.basename(root)
                targets.append({
                    "app": app_name,
                    "cve": match.group(1).upper(),
                    "path": os.path.join(root, dir_name)
                })
    return targets

def fetch_cve_metrics(cve_id, retry_count=3):
    if retry_count <= 0:
        print(f"[-] 达到最大重试次数，放弃: {cve_id}")
        return None, None
        
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None, None
            
            metrics = vulns[0]["cve"].get("metrics", {})
            # 优先提取 V3.1 -> V3.0 -> V2
            cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2", [])
            
            if cvss_list:
                cvss_item = cvss_list[0]
                score = cvss_item.get("exploitabilityScore")
                # 提取攻击向量 (V3用 attackVector，V2用 accessVector)
                cvss_data = cvss_item.get("cvssData", {})
                attack_vector = cvss_data.get("attackVector") or cvss_data.get("accessVector")
                return score, attack_vector
            
        elif response.status_code in [403, 429]:
            print(f"[-] 触发 NVD 限流，等待后重试: {cve_id} (剩余重试: {retry_count-1})")
            time.sleep(6) # 退避策略
            return fetch_cve_metrics(cve_id, retry_count - 1)
            
    except Exception as e:
        print(f"[-] 请求异常 {cve_id}: {e}")
        
    return None, None

def categorize_difficulty(score):
    if score is None:
        return "Unknown"
    
    try:
        score = float(score)
        if score > 3.0:
            return "Easy"
        elif 2.0 <= score <= 3.0:
            return "Medium"
        else:
            return "Hard"
    except ValueError:
        return "Unknown"

def main():
    print("[*] 开始扫描 Vulhub 目录...")
    targets = get_vulhub_cves(VULHUB_DIR)
    print(f"[*] 共发现 {len(targets)} 个包含 CVE 的靶机。")
    
    results = []
    
    for idx, target in enumerate(targets):
        cve_id = target["cve"]
        print(f"[{idx+1}/{len(targets)}] 正在获取 {cve_id} 的评分...")
        
        score, attack_vector = fetch_cve_metrics(cve_id)
        difficulty = categorize_difficulty(score)
        
        results.append({
            "App": target["app"],
            "CVE": cve_id,
            "Exploitability_Score": score if score is not None else "N/A",
            "Attack_Vector": attack_vector if attack_vector else "Unknown",
            "Difficulty": difficulty,
            "Path": target["path"]
        })
        
        # NVD 接口限流控制 (有 Key 时可适当缩短)
        time.sleep(0.6 if NVD_API_KEY else 6)
        
    # 保存结果
    with open('vulhub_difficulty_mapping.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["App", "CVE", "Exploitability_Score", "Attack_Vector", "Difficulty", "Path"])
        writer.writeheader()
        writer.writerows(results)
        
    print("[+] 靶机难度矩阵生成完毕: vulhub_difficulty_mapping.csv")

if __name__ == "__main__":
    main()