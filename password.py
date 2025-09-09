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
LANGUAGE = "en_us"  # 可选 "zh_cn"
# -------------------------------------------------------

import os
import sys
import re
import tempfile
import subprocess
import getpass
import hashlib
import datetime
import json
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

# ---------- 翻译 i18n ----------
class I18n:
    def __init__(self, lang="en_us"):
        base_path = os.path.join(os.path.dirname(__file__), "locales")
        lang_file = os.path.join(base_path, f"{lang}.json")
        if not os.path.exists(lang_file):
            lang_file = os.path.join(base_path, "en_us.json")
        with open(lang_file, "r", encoding="utf-8") as f:
            self.translations = json.load(f)

    def t(self, key, **kwargs):
        text = self.translations.get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except Exception:
                pass
        return text

LANG = os.environ.get("APP_LANG", LANGUAGE)   # 默认英文，可以通过环境变量切换
_ = I18n(LANG).t

# ---------- 工具函数 ----------

def check_gpg_installed():
    if which("gpg") is None:
        print(_("error_gpg_not_found"), file=sys.stderr)
        input(_('enter_to_exit'))
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
        print(_("gpg_card_status_error"), file=sys.stderr)
        try:
            print(p.stdout.decode(errors="ignore"), file=sys.stderr)
        except Exception:
            print(p.stdout, file=sys.stderr)
        input(_('enter_to_exit'))
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
        _("result_hash"),
        f"\t{hex_line}",
        "",
        _("result_password"),
        f"\t{final_pw}",
        "",
        _("result_note")
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
    # 修复变量作用域问题
    global _

    check_gpg_installed()

    # 校验 FAKE_TIME 格式
    if not validate_fake_time(FAKE_TIME.strip() if FAKE_TIME else ""):
        print(_("fake_time_format_error"), file=sys.stderr)
        input(_('enter_to_exit'))
        sys.exit(1)

    card_text = get_card_status_text()
    print(_("gpg_card_status_output"))
    for i,l in enumerate(card_text.splitlines()):
        if i>=8: break
        print(l)

    keyid, algo, created = parse_keyid_algo_and_created(card_text)
    if not keyid:
        print(_("unknown_keyid"), file=sys.stderr)
        input(_('enter_to_exit'))
        sys.exit(2)
    created_fake = dt_to_gpg_fake_time(created) if created else None

    requested = FAKE_TIME.strip() if FAKE_TIME else None
    if requested:
        actual_fake = dt_to_gpg_fake_time(requested) or requested
    else:
        actual_fake = created_fake or "20000101T000000"

    print(_("fake_time_note", actual_fake=actual_fake, requested=requested or "None", created_fake=created_fake or "None"))

    if algo:
        al = algo.lower()
        if al.startswith("dsa"):
            ans = input(_("EdDSA_detected")).strip().lower()
            if ans != "y":
                print(_("exit"))
                input(_('enter_to_exit'))
                sys.exit(3)

    username = USERNAME.strip() if USERNAME else ""
    if not username:
        username = input(_("input_username")).strip()

    domain_raw = DOMAIN_OVERRIDE.strip() if DOMAIN_OVERRIDE else ""
    if not domain_raw:
        domain_raw = input(_("input_domain")).strip()
    domain = normalize_domain(domain_raw)

    # 输入口令（两次确认）
    pwd1 = getpass.getpass(_("input_password")).encode("utf-8")
    pwd2 = getpass.getpass(_("input_password_confirm")).encode("utf-8")
    if pwd1 != pwd2:
        print(_("error_password_mismatch"), file=sys.stderr)
        input(_('enter_to_exit'))
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
        print(_("desired_chars_adjusted", desired_chars=DESIRED_CHARS, out_chars=out_chars, max_chars=max_chars))

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
    print(_("signing_first"))
    p1 = sign_with_time(chpath, sig1, actual_fake)
    print(p1.stdout.decode(errors="ignore"))

    if not os.path.exists(sig1):
        print(_("sig1_not_found"))
        print(_("tmp_dir", tmpd=tmpd))
        input(_('enter_to_exit'))
        sys.exit(4)


    ts1, _dump = parse_sig_created_unix(sig1)
    mpi1, _dump = parse_sig_mpi(sig1)

    # 强制第二次签名使用与第一次相同的 fake time，避免 ±1 秒差异
    use_fake_for_second = actual_fake
    print(_("check_fake_time", use_fake_for_second=use_fake_for_second))

    try:
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False)
    except Exception:
        pass

    # 第 2 次签名
    print(_("signing_second"))
    p2 = sign_with_time(chpath, sig2, use_fake_for_second)
    print(p2.stdout.decode(errors="ignore"))
    if not os.path.exists(sig2):
        print(_("sig2_not_found"))
        print(_("tmp_dir", tmpd=tmpd))
        input(_('enter_to_exit'))
        sys.exit(5)

    ts2, _dump = parse_sig_created_unix(sig2)
    mpi2, _dump = parse_sig_mpi(sig2)

    # 新增：对比 fake_time 与签名 created 时间戳，遇到不符时打印提示框
    def print_time_box(file_name, ts, fake_time):
        if ts is None:
            print(_("sig_created_timestamp_not_parsed", file_name=file_name))
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
        print(_("time_mismatch_warning", file_name="sig1.bin"))
        print_time_box("sig1.bin", ts1, actual_fake)
        box_printed = True
    if ts2 is not None and fake_ts is not None and ts2 != fake_ts:
        print(_("time_mismatch_warning", file_name="sig2.bin"))
        print_time_box("sig2.bin", ts2, actual_fake)
        box_printed = True
    if box_printed:
        print(_("time_mismatch_note"))


    # 处理 MPI 与可能的多个输出
    results = []  # 每项 (tag, data_bytes_for_pepper)
    if (mpi1 is not None) and (mpi2 is not None):
        h1 = hashlib.sha256(mpi1).hexdigest()
        h2 = hashlib.sha256(mpi2).hexdigest()
        print(f"{_('mpi1_sha256', h1=h1)}\n{_('mpi2_sha256', h2=h2)}")
        if h1 == h2:
            print(_("mpi_consistent"))
            results.append(("MPI (一致)", mpi1))
        else:
            print(_("mpi_mismatch_warning"))
            results.append(("MPI1", mpi1))
            results.append(("MPI2", mpi2))
    elif (mpi1 is not None) and (mpi2 is None):
        print(_("only_sig1_mpi"))
        results.append(("MPI1", mpi1))
    elif (mpi1 is None) and (mpi2 is not None):
        print(_("only_sig2_mpi"))
        results.append(("MPI2", mpi2))
    else:
        print(_("no_mpi_fallback"))
        sig2_bytes = open(sig2, "rb").read()
        results.append(("sig2.bin (full)", sig2_bytes))


    # 新增：派生结果与时间戳对比，框内外显示
    def print_time_and_pw_box(file_name, ts, fake_time, hex_out, final_pw):
        dt_utc = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        lines = [
        _("sig_created_timestamp", file_name=file_name, ts=ts),
        _("utc_time", utc_time=dt_utc.strftime('%Y-%m-%d %H:%M:%S')),
        _("fake_time_value", fake_time=fake_time)
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
                print(_("sig_info_and_password", file_name="sig2.bin"))
                print(_("sig_created_timestamp", file_name="sig2.bin", ts=ts2))
                if ts2 is not None:
                    dt_utc2 = datetime.datetime.fromtimestamp(ts2, datetime.timezone.utc)
                    print(_("utc_time", utc_time=dt_utc2.strftime('%Y-%m-%d %H:%M:%S')))
                    print(_("sig_hash", file_name="sig2.bin", hash=derived_results[1]['hex_out']))
                    print(_("derived_password", file_name="sig2.bin", password=derived_results[1]['final_pw']))
            print(_("time_correct_sig_info", file_name="sig1.bin"))
            print_time_and_pw_box("sig1.bin", ts1, actual_fake, derived_results[0]["hex_out"], derived_results[0]["final_pw"])
        else:
            # 框外：另一个文件信息与密码
            print(_("sig_info_and_password", file_name="sig1.bin"))
            print(_("sig_created_timestamp", file_name="sig1.bin", ts=ts1))
            if ts1 is not None:
                dt_utc1 = datetime.datetime.fromtimestamp(ts1, datetime.timezone.utc)
                print(_("utc_time", utc_time=dt_utc1.strftime('%Y-%m-%d %H:%M:%S')))
                print(_("sig_hash", file_name="sig1.bin", hash=derived_results[0]['hex_out']))
                print(_("derived_password", file_name="sig1.bin", password=derived_results[0]['final_pw']))
            print(_("time_correct_sig_info", file_name="sig2.bin"))
        # 框外：另一个文件信息与密码
    else:
        # 都不对得上，按原逻辑输出
        for dr in derived_results:
            print(_("derived_result_based_on", tag=dr['tag']))
            print_boxed(dr["hex_out"], dr["final_pw"])

    if not use_argon2:
        print(_("argon2_not_found"))
        input(_('enter_to_exit'))

    print(_("script_finished", tmpd=tmpd))
    print(_("script_note"))
    input(_('enter_to_exit'))

if __name__ == "__main__":
    main()