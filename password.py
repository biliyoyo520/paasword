#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
derive_with_topvars.py  （方案 B，MPI 派生最终版，支持多结果输出与自定义字符集）

功能要点：
 - challenge 内容写入：DERIVE|domain|username|sha256(pwd)|v1  （避免明文密码写入）
 - 优先解析签名中的 MPI（RSA 的 data / ECDSA/EdDSA/DSA 的 r||s），对 MPI 做 SHA256 得到 pepper
 - 若两次签名的 MPI 不一致，则分别用两者派生并输出两个结果（便于对比）
 - 若无法解析 MPI，则退回使用 sig2 的二进制做 SHA256（降级方案）
 - 支持自定义字符集（去掉易混淆字符 i I l o O，并包含 !@#）
"""

# -------------------- 可编辑变量区 --------------------
FAKE_TIME = "20260802T103000"  # 可留空；如提供，须为 "YYYYMMDDThhmmss"
USERNAME = ""
DOMAIN_OVERRIDE = ""
DESIRED_CHARS = 20
# -------------------------------------------------------

import os
import sys
import re
import tempfile
import subprocess
import getpass
import hashlib
import datetime
from urllib.parse import urlparse
from shutil import which
from wcwidth import wcswidth

# KDF / encoding config
DKLEN_BYTES = 32
PBKDF2_ITER = 200_000
VERSION_TAG = "v1"

# 自定义字符集（按你要求）
OUTPUT_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ1234567890!@#"

# Try argon2
use_argon2 = False
try:
    import argon2.low_level as argon2_low
    from argon2.low_level import Type as Argon2Type
    use_argon2 = True
except Exception:
    use_argon2 = False

# ---------- 工具函数 ----------

def check_gpg_installed():
    if which("gpg") is None:
        print("错误：未找到 gpg。请先安装 GnuPG 并确保 gpg 在 PATH 中。", file=sys.stderr)
        input('按下 <Enter> 退出')
        sys.exit(1)

def run_cmd_bytes(cmd, timeout=None):
    """Run cmd and return CompletedProcess (stdout in bytes)."""
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=124, stdout=b"<timeout>\n")

def get_card_status_text():
    p = run_cmd_bytes(["gpg", "--card-status"], timeout=15)
    if p.returncode != 0:
        print("gpg --card-status 返回错误：", file=sys.stderr)
        try:
            print(p.stdout.decode(errors="ignore"), file=sys.stderr)
        except Exception:
            print(p.stdout, file=sys.stderr)
        input('按下 <Enter> 退出')
        sys.exit(2)
    return p.stdout.decode(errors="ignore")

def parse_keyid_algo_and_created(card_text):
    keyid = None; algo = None
    for line in card_text.splitlines():
        line = line.strip()
        if line.startswith("sec") or line.startswith("pub"):
            m = re.search(r"([a-zA-Z0-9]+)/([0-9A-Fa-f]{8,40})", line)
            if m:
                algo = m.group(1); keyid = m.group(2)
                break
    created = None
    created_re = re.compile(r"created\s*\.{0,}\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})")
    lines = card_text.splitlines()
    sig_idx = None
    for i,l in enumerate(lines):
        if "Signature key" in l or l.strip().lower().startswith("signature key"):
            sig_idx = i; break
    if sig_idx is not None:
        for j in range(sig_idx, min(sig_idx+8, len(lines))):
            m = created_re.search(lines[j])
            if m:
                created = m.group(1); break
    if not created:
        for l in lines:
            m = created_re.search(l)
            if m:
                created = m.group(1); break
    return keyid, algo, created

def dt_to_gpg_fake_time(dt_str):
    if not dt_str:
        return None
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})", dt_str)
    if m:
        y,mo,d,h,mi,s = m.groups()
        return f"{y}{mo}{d}T{h}{mi}{s}"
    m2 = re.match(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})", dt_str)
    if m2:
        return dt_str
    return None

def validate_fake_time(s):
    if not s:
        return True
    return re.fullmatch(r"\d{8}T\d{6}", s) is not None

def normalize_domain(domain_input: str) -> str:
    if "://" in domain_input:
        parsed = urlparse(domain_input.strip())
        return (parsed.hostname or domain_input.strip()).lower()
    return domain_input.strip().lower()

def bytes_to_bitstring(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def derive_argon2(secret: bytes, salt: bytes, dklen: int):
    return argon2_low.hash_secret_raw(secret=secret, salt=salt,
                                      time_cost=2, memory_cost=65536,
                                      parallelism=1, hash_len=dklen,
                                      type=Argon2Type.ID)

def derive_pbkdf2(secret: bytes, salt: bytes, dklen: int):
    return hashlib.pbkdf2_hmac("sha256", secret, salt, PBKDF2_ITER, dklen)

def print_boxed(hex_line: str, final_pw: str):
    lines = [
        "Done!",
        "Hash结果：",
        f"\t{hex_line}",
        "",
        "最终密码：",
        f"\t{final_pw}",
        "",
        "提示：复制完整的一整行密码（避免只取末尾部分）"
    ]
    width = max(wcswidth(ln) for ln in lines) + 8
    print("┌" + "─"*(width-2) + "┐")
    for ln in lines:
        padding = width - 4 - wcswidth(ln)
        print("│ " + ln + " " * padding + " │")
    print("└" + "─"*(width-2) + "┘")

def sign_with_time(chpath, outfn, fake_time):
    """执行签名；使用 "=" 形式避免 Windows 解析问题。"""
    if os.path.exists(outfn):
        os.remove(outfn)
    cmd = [
        "gpg",
        f"--faked-system-time={fake_time}",
        "--digest-algo", "SHA256",
        "--detach-sign",
        "--output", outfn,
        chpath,
    ]
    p = run_cmd_bytes(cmd)
    return p

def parse_sig_created_unix(sigfile):
    p = run_cmd_bytes(["gpg", "--list-packets", "--verbose", sigfile], timeout=15)
    out = p.stdout.decode(errors="ignore")
    m = re.search(r"created\s+(\d+)", out)
    if m:
        try:
            return int(m.group(1)), out
        except Exception:
            return None, out
    return None, out

def _collect_hex_chunks_from_line(line: str) -> str:
    return "".join(ch for ch in line if ch in "0123456789abcdefABCDEF")

def parse_sig_mpi(sigfile):
    """
    解析签名主体（MPI）：
      - RSA：'data:' 后的十六进制（可能多行），聚合后作为单一 MPI。
      - ECDSA/EdDSA/DSA：解析 'r:' 与 's:' 两个 MPI，按 r||s 拼接。
    返回 (bytes or None, full_dump_text)
    """
    p = run_cmd_bytes(["gpg", "--list-packets", "--verbose", sigfile], timeout=15)
    out = p.stdout.decode(errors="ignore")
    lines = out.splitlines()

    # 1) RSA 的 "data:" 聚合
    hex_parts = []
    collecting = False
    for line in lines:
        if "data:" in line:
            idx = line.find("data:") + len("data:")
            part = _collect_hex_chunks_from_line(line[idx:])
            if part:
                hex_parts.append(part)
            collecting = True
            continue
        if collecting:
            if re.match(r"^\s*[0-9A-Fa-f ]+$", line):
                h = _collect_hex_chunks_from_line(line)
                if h:
                    hex_parts.append(h)
                continue
            else:
                break
    if hex_parts:
        try:
            return bytes.fromhex("".join(hex_parts)), out
        except Exception:
            pass

    # 2) ECDSA/EdDSA/DSA 的 r/s 形式
    r_hex = None; s_hex = None
    for line in lines:
        m_r = re.search(r"\br:\s*([0-9A-Fa-f ][0-9A-Fa-f ]+)$", line)
        m_s = re.search(r"\bs:\s*([0-9A-Fa-f ][0-9A-Fa-f ]+)$", line)
        if m_r:
            r_hex = _collect_hex_chunks_from_line(m_r.group(1))
        if m_s:
            s_hex = _collect_hex_chunks_from_line(m_s.group(1))
    if r_hex and s_hex:
        try:
            return bytes.fromhex(r_hex + s_hex), out
        except Exception:
            return None, out

    return None, out

# ---------- 新的 bits->alphabet 映射函数 ----------
def bits_to_crockford(bitstr: str, out_chars: int) -> str:
    """
    将比特串映射到用户指定字符表（OUTPUT_ALPHABET）。
    - 使用每字符所需的最小 bit 数（bits_per_char）进行切分。
    - 当生成的整数超出字符表时，使用取模（val % n）以利用全部 bits。
    - 保证 deterministic。
    """
    ALPH = OUTPUT_ALPHABET
    n = len(ALPH)
    # 计算每字符需要的 bits
    bits_per_char = 1
    while (1 << bits_per_char) < n:
        bits_per_char += 1

    needed_bits = bits_per_char * out_chars
    if len(bitstr) < needed_bits:
        bitstr = bitstr.ljust(needed_bits, "0")
    else:
        bitstr = bitstr[:needed_bits]

    chars = []
    for i in range(0, needed_bits, bits_per_char):
        val = int(bitstr[i:i+bits_per_char], 2)
        val = val % n
        chars.append(ALPH[val])
    return "".join(chars)

# ---------- 主流程 ----------
def main():
    check_gpg_installed()

    # 校验 FAKE_TIME 格式
    if not validate_fake_time(FAKE_TIME.strip() if FAKE_TIME else ""):
        print("错误：FAKE_TIME 必须形如 YYYYMMDDThhmmss（或留空）", file=sys.stderr)
        input('按下 <Enter> 退出')
        sys.exit(1)

    card_text = get_card_status_text()
    print("gpg --card-status 部分输出（前几行）：")
    for i,l in enumerate(card_text.splitlines()):
        if i>=8: break
        print(l)

    keyid, algo, created = parse_keyid_algo_and_created(card_text)
    if not keyid:
        print("未在卡上解析到 keyid，请确认卡可用。", file=sys.stderr)
        input('按下 <Enter> 退出')
        sys.exit(2)
    created_fake = dt_to_gpg_fake_time(created) if created else None

    requested = FAKE_TIME.strip() if FAKE_TIME else None
    if requested:
        actual_fake = dt_to_gpg_fake_time(requested) or requested
    else:
        actual_fake = created_fake or "20000101T000000"

    print(f"使用的 faked-system-time = {actual_fake} (请求: {requested}, 卡创建: {created_fake})")

    if algo:
        al = algo.lower()
        if al.startswith("dsa"):
            ans = input("检测到 DSA：某些实现对 k 使用随机数，可能导致不可复现。仍要继续尝试吗？(y/N): ").strip().lower()
            if ans != "y":
                print("退出。")
                input('按下 <Enter> 退出')
                sys.exit(3)

    username = USERNAME.strip() if USERNAME else ""
    if not username:
        username = input("请输入用户名（login）：").strip()

    domain_raw = DOMAIN_OVERRIDE.strip() if DOMAIN_OVERRIDE else ""
    if not domain_raw:
        domain_raw = input("请输入站点域名或 URL：").strip()
    domain = normalize_domain(domain_raw)

    # 输入口令（两次确认）
    pwd1 = getpass.getpass("请输入你的简单密码（回车后不回显）：").encode("utf-8")
    pwd2 = getpass.getpass("请再次输入你的简单密码（回车后不回显）：").encode("utf-8")
    if pwd1 != pwd2:
        print("错误：两次输入的密码不一致，请重新运行脚本。", file=sys.stderr)
        input('按下 <Enter> 退出')
        sys.exit(7)
    pwd = pwd1

    # 依据 OUTPUT_ALPHABET 计算最大可表达字符数
    alph_len = len(OUTPUT_ALPHABET)
    bits_per_char = 1
    while (1 << bits_per_char) < alph_len:
        bits_per_char += 1
    max_chars = (DKLEN_BYTES * 8) // bits_per_char
    out_chars = max(1, min(DESIRED_CHARS, max_chars))
    if out_chars != DESIRED_CHARS:
        print(f"提示：DESIRED_CHARS 已从 {DESIRED_CHARS} 调整为 {out_chars}（上限 {max_chars}）。")

    tmpd = tempfile.mkdtemp(prefix="gpgderive_")
    chpath = os.path.join(tmpd, "challenge.txt")
    sig1 = os.path.join(tmpd, "sig1.bin")
    sig2 = os.path.join(tmpd, "sig2.bin")

    # challenge 写入密码哈希而非明文密码
    pwd_hash_hex = hashlib.sha256(pwd).hexdigest()
    with open(chpath, "wb") as f:
        f.write(f"DERIVE|{domain}|{username}|{pwd_hash_hex}|{VERSION_TAG}".encode("utf-8"))

    try:
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False)
    except Exception:
        pass

    # 第 1 次签名
    print("进行第 1 次签名（可能需要 PIN / touch）：")
    p1 = sign_with_time(chpath, sig1, actual_fake)
    print(p1.stdout.decode(errors="ignore"))

    if not os.path.exists(sig1):
        print("第 1 次签名未生成签名文件，请检查 gpg 输出并重试。")
        print(f"临时目录：{tmpd}")
        input('按下 <Enter> 退出')
        sys.exit(4)


    ts1, _ = parse_sig_created_unix(sig1)
    mpi1, _ = parse_sig_mpi(sig1)

    # 强制第二次签名使用与第一次相同的 fake time，避免 ±1 秒差异
    use_fake_for_second = actual_fake
    print(f"第二次签名强制使用相同的 faked-system-time = {use_fake_for_second}")

    try:
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False)
    except Exception:
        pass

    # 第 2 次签名
    print("进行第 2 次签名（可能需要 PIN / touch）：")
    p2 = sign_with_time(chpath, sig2, use_fake_for_second)
    print(p2.stdout.decode(errors="ignore"))
    if not os.path.exists(sig2):
        print("第 2 次签名未生成签名文件，请检查 gpg 输出并重试。")
        print(f"临时目录：{tmpd}")
        input('按下 <Enter> 退出')
        sys.exit(5)

    ts2, _ = parse_sig_created_unix(sig2)
    mpi2, _ = parse_sig_mpi(sig2)

    # 新增：对比 fake_time 与签名 created 时间戳，遇到不符时打印提示框
    def print_time_box(file_name, ts, fake_time):
        if ts is None:
            print(f"{file_name} 未能解析到 created 时间戳。")
            return
        dt_utc = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        print("┌" + "─"*44 + "┐")
        print(f"│ {file_name} created时间戳: {ts} │")
        print(f"│ UTC时间: {dt_utc.strftime('%Y-%m-%d %H:%M:%S')} │")
        print(f"│ fake_time: {fake_time} │")
        print("└" + "─"*44 + "┘")

    # 将 fake_time 转为时间戳
    def fake_time_to_ts(fake_time):
        try:
            dt = datetime.datetime.strptime(fake_time, "%Y%m%dT%H%M%S")
            return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
        except Exception:
            return None

    fake_ts = fake_time_to_ts(actual_fake)
    box_printed = False
    if ts1 is not None and fake_ts is not None and ts1 != fake_ts:
        print("\n==== 时间不符警告（sig1.bin） ====")
        print_time_box("sig1.bin", ts1, actual_fake)
        box_printed = True
    if ts2 is not None and fake_ts is not None and ts2 != fake_ts:
        print("\n==== 时间不符警告（sig2.bin） ====")
        print_time_box("sig2.bin", ts2, actual_fake)
        box_printed = True
    if box_printed:
        print("\n【注意】签名时间与 fake_time 不符，可能导致密码不一致。请检查时间设置或重试。\n")


    # 处理 MPI 与可能的多个输出
    results = []  # 每项 (tag, data_bytes_for_pepper)
    if (mpi1 is not None) and (mpi2 is not None):
        h1 = hashlib.sha256(mpi1).hexdigest()
        h2 = hashlib.sha256(mpi2).hexdigest()
        print(f"MPI1 SHA256={h1}\nMPI2 SHA256={h2}")
        if h1 == h2:
            print("MPI 一致：使用该 MPI 派生 pepper。")
            results.append(("MPI (一致)", mpi1))
        else:
            print("警告：两次签名的 MPI 不一致！将分别派生两个密码以便对比。")
            results.append(("MPI1", mpi1))
            results.append(("MPI2", mpi2))
    elif (mpi1 is not None) and (mpi2 is None):
        print("仅解析到 sig1 的 MPI：使用 sig1 的 MPI。")
        results.append(("MPI1", mpi1))
    elif (mpi1 is None) and (mpi2 is not None):
        print("仅解析到 sig2 的 MPI：使用 sig2 的 MPI。")
        results.append(("MPI2", mpi2))
    else:
        print("未能解析到任一 MPI，回退使用 sig2 的二进制 SHA256 作为 pepper（次优）。")
        sig2_bytes = open(sig2, "rb").read()
        results.append(("sig2.bin (full)", sig2_bytes))


    # 新增：派生结果与时间戳对比，框内外显示
    def print_time_and_pw_box(file_name, ts, fake_time, hex_out, final_pw):
        dt_utc = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        lines = [
        f"{file_name} created时间戳: {ts}",
        f"UTC时间: {dt_utc.strftime('%Y-%m-%d %H:%M:%S')}",
        f"fake_time: {fake_time}"
                ]
        width = max(wcswidth(ln) for ln in lines) + 4  # 加上边框和空格
        print("┌" + "─"*(width-2) + "┐")
        for ln in lines:
            padding = width - 4 - wcswidth(ln)
            print("│ " + ln + " " * padding + " │")
        print("└" + "─"*(width-2) + "┘")
        print_boxed(hex_out, final_pw)
        
    # 记录每个结果的派生信息
    derived_results = []
    for idx, (tag, data) in enumerate(results):
        pepper = hashlib.sha256(data).digest()
        secret_material = pwd + b"|" + username.encode("utf-8") + b"|" + pepper
        salt = domain.encode("utf-8") + b"|" + keyid.encode("utf-8") + b"|" + VERSION_TAG.encode("utf-8")

        if use_argon2:
            derived = derive_argon2(secret_material, salt, DKLEN_BYTES)
        else:
            derived = derive_pbkdf2(secret_material, salt, DKLEN_BYTES)

        hex_out = derived.hex()
        bstr = bytes_to_bitstring(derived)
        final_pw = bits_to_crockford(bstr, out_chars)
        derived_results.append({
            "idx": idx,
            "tag": tag,
            "hex_out": hex_out,
            "final_pw": final_pw
        })

    # 判断 sig1/sig2 哪个时间戳对得上
    sig1_match = ts1 is not None and fake_ts is not None and ts1 == fake_ts
    sig2_match = ts2 is not None and fake_ts is not None and ts2 == fake_ts

    # 框内外显示逻辑
    if sig1_match or sig2_match:
        # 框内：时间对得上的文件
        if sig1_match:
            # 框外：另一个文件信息与密码
            if len(derived_results) > 1:
                print(f"\n=== sig2.bin 信息与派生密码===")
                print(f"sig2.bin created时间戳: {ts2}")
                if ts2 is not None:
                    dt_utc2 = datetime.datetime.fromtimestamp(ts2, datetime.timezone.utc)
                    print(f"UTC时间: {dt_utc2.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"sig2.bin hash：{derived_results[1]['hex_out']}")
                    print(f"sig2.bin 派生密码：{derived_results[1]['final_pw']}")
            print("\n=== 【时间正确】 sig1.bin 信息===")
            print_time_and_pw_box("sig1.bin", ts1, actual_fake, derived_results[0]["hex_out"], derived_results[0]["final_pw"])
        else:
            # 框外：另一个文件信息与密码
            print(f"\n=== sig1.bin 信息与派生密码===")
            print(f"sig1.bin created时间戳: {ts1}")
            if ts1 is not None:
                dt_utc1 = datetime.datetime.fromtimestamp(ts1, datetime.timezone.utc)
                print(f"UTC时间: {dt_utc1.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"sig1.bin hash：{derived_results[0]['hex_out']}")
                print(f"sig1.bin 派生密码：{derived_results[0]['final_pw']}")
            print("\n=== 【时间正确】 sig2.bin 信息===")
            print_time_and_pw_box("sig2.bin", ts2, actual_fake, derived_results[-1]["hex_out"], derived_results[-1]["final_pw"])
    else:
        # 都不对得上，按原逻辑输出
        for dr in derived_results:
            print(f"\n=== 基于 {dr['tag']} 的派生结果 ===")
            print_boxed(dr["hex_out"], dr["final_pw"])

    if not use_argon2:
        print("\n提示：未检测到 argon2-cffi，已使用 PBKDF2 作为退路。要更强安全请安装 argon2-cffi。")
        input('按下 <Enter> 退出')

    print("\n脚本完成。若要保留或删除临时签名文件，请查看：", tmpd)
    print("提示：本脚本使用 MPI 派生模式；只要 key 与输入（域名、用户名、口令）一致，结果在不同设备/时间应保持稳定。")
    input('按下 <Enter> 退出')

if __name__ == "__main__":
    main()
