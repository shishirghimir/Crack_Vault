import hashlib
import threading
import time
import os
import sys
import itertools
import string
import zipfile
import struct

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    HAS_TK = True
except ImportError:
    HAS_TK = False


# =============================================================================
# CUSTOM DATA STRUCTURES
# =============================================================================

class Node:
    __slots__ = ('key', 'value', 'next')
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.next = None


class HashMap:
    def __init__(self, capacity=256):
        self._capacity = capacity
        self._size = 0
        self._buckets = [None] * capacity

    def _hash(self, key):
        h = 5381
        for ch in str(key):
            h = ((h << 5) + h + ord(ch)) & 0xFFFFFFFF
        return h % self._capacity

    def put(self, key, value):
        idx = self._hash(key)
        node = self._buckets[idx]
        while node:
            if node.key == key:
                node.value = value
                return
            node = node.next
        new_node = Node(key, value)
        new_node.next = self._buckets[idx]
        self._buckets[idx] = new_node
        self._size += 1
        if self._size > self._capacity * 0.75:
            self._resize()

    def get(self, key, default=None):
        idx = self._hash(key)
        node = self._buckets[idx]
        while node:
            if node.key == key:
                return node.value
            node = node.next
        return default

    def contains(self, key):
        return self.get(key) is not None

    def remove(self, key):
        idx = self._hash(key)
        node = self._buckets[idx]
        prev = None
        while node:
            if node.key == key:
                if prev:
                    prev.next = node.next
                else:
                    self._buckets[idx] = node.next
                self._size -= 1
                return True
            prev = node
            node = node.next
        return False

    def keys(self):
        result = []
        for bucket in self._buckets:
            node = bucket
            while node:
                result.append(node.key)
                node = node.next
        return result

    def values(self):
        result = []
        for bucket in self._buckets:
            node = bucket
            while node:
                result.append(node.value)
                node = node.next
        return result

    def items(self):
        result = []
        for bucket in self._buckets:
            node = bucket
            while node:
                result.append((node.key, node.value))
                node = node.next
        return result

    def size(self):
        return self._size

    def _resize(self):
        old = self._buckets
        self._capacity *= 2
        self._buckets = [None] * self._capacity
        self._size = 0
        for bucket in old:
            node = bucket
            while node:
                self.put(node.key, node.value)
                node = node.next


class QueueNode:
    __slots__ = ('data', 'next')
    def __init__(self, data):
        self.data = data
        self.next = None


class Queue:
    def __init__(self):
        self._front = None
        self._rear = None
        self._size = 0

    def enqueue(self, data):
        node = QueueNode(data)
        if self._rear:
            self._rear.next = node
        self._rear = node
        if not self._front:
            self._front = node
        self._size += 1

    def dequeue(self):
        if not self._front:
            return None
        data = self._front.data
        self._front = self._front.next
        if not self._front:
            self._rear = None
        self._size -= 1
        return data

    def peek(self):
        return self._front.data if self._front else None

    def is_empty(self):
        return self._size == 0

    def size(self):
        return self._size

    def to_list(self):
        result = []
        node = self._front
        while node:
            result.append(node.data)
            node = node.next
        return result


class TrieNode:
    __slots__ = ('children', 'is_end', 'word')
    def __init__(self):
        self.children = {}
        self.is_end = False
        self.word = None


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word):
        node = self.root
        for ch in word:
            if ch not in node.children:
                node.children[ch] = TrieNode()
            node = node.children[ch]
        node.is_end = True
        node.word = word

    def search_prefix(self, prefix):
        node = self.root
        for ch in prefix:
            if ch not in node.children:
                return []
            node = node.children[ch]
        results = []
        self._collect(node, results)
        return results

    def _collect(self, node, results):
        if node.is_end:
            results.append(node.word)
        for child in node.children.values():
            self._collect(child, results)


# =============================================================================
# HASH ENGINE
# =============================================================================

class HashEngine:
    ALGORITHMS = HashMap()

    @staticmethod
    def _init_algorithms():
        algos = [
            ('md5', 32), ('sha1', 40), ('sha224', 56), ('sha256', 64),
            ('sha384', 96), ('sha512', 128), ('sha3_224', 56), ('sha3_256', 64),
            ('sha3_384', 96), ('sha3_512', 128), ('blake2b', 128), ('blake2s', 64),
        ]
        for name, length in algos:
            HashEngine.ALGORITHMS.put(name, length)

    @staticmethod
    def compute(text, algo='md5'):
        fn = getattr(hashlib, algo, None)
        if fn is None:
            return None
        return fn(text.encode('utf-8')).hexdigest()

    @staticmethod
    def identify_hash(hash_str):
        hash_len = len(hash_str.strip())
        matches = []
        for name, length in HashEngine.ALGORITHMS.items():
            if length == hash_len:
                matches.append(name)
        return matches

    @staticmethod
    def supported_algorithms():
        return HashEngine.ALGORITHMS.keys()


HashEngine._init_algorithms()


# =============================================================================
# KEYWORD PATTERN FILTER (Priority Cracking)
# =============================================================================

class KeywordFilter:
    def __init__(self):
        self.trie = Trie()
        self.keywords = []

    def set_keywords(self, keyword_string):
        raw = keyword_string.replace(',', ' ')
        self.keywords = [k.strip().lower() for k in raw.split() if k.strip()]
        self.trie = Trie()
        for kw in self.keywords:
            self.trie.insert(kw)

    def _strip_specials(self, word):
        return ''.join(ch for ch in word if ch.isalnum()).lower()

    def _generate_keyword_mutations(self):
        seen = HashMap()
        mutations = Queue()
        specials = ['!', '@', '#', '$', '%', '&', '*', '.', '-', '_', '~', '+', '=']
        suffixes = ['', '1', '12', '123', '1234', '!', '!!', '@', '#', '$',
                    '01', '99', '2024', '2025', '2026', '007', '69', '666',
                    '0', '00', '11', '22', '33', '44', '55', '77', '88',
                    '!@', '!@#', '@!', '#1', '$1', '1!', '123!', '1234!']
        prefixes = ['', '!', '@', '#', '$', '1', '123', '!@', '!@#']
        for kw in self.keywords:
            bases = [kw, kw.upper(), kw.capitalize(), kw.swapcase(), kw[::-1], kw + kw]
            leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7', 'l': '1', 'g': '9', 'b': '8'}
            leet = list(kw.lower())
            for idx, ch in enumerate(leet):
                if ch in leet_map:
                    leet[idx] = leet_map[ch]
            bases.append(''.join(leet))
            bases.append(''.join(leet).capitalize())
            dashed = '-'.join(kw)
            dotted = '.'.join(kw)
            under = '_'.join(kw)
            bases.extend([dashed, dotted, under])
            for b in bases:
                for s in suffixes:
                    for p in prefixes:
                        candidate = p + b + s
                        if not seen.contains(candidate):
                            seen.put(candidate, True)
                            mutations.enqueue(candidate)
                for sp in specials:
                    for variant in [sp + b, b + sp, sp + b + sp]:
                        if not seen.contains(variant):
                            seen.put(variant, True)
                            mutations.enqueue(variant)
        multi = []
        if len(self.keywords) >= 2:
            for i in range(len(self.keywords)):
                for j in range(len(self.keywords)):
                    if i != j:
                        for sep in ['', ' ', '_', '-', '.', '!', '@', '#', '1', '123']:
                            for combo_fn in [lambda a, b, s: a + s + b,
                                             lambda a, b, s: a.capitalize() + s + b,
                                             lambda a, b, s: a + s + b.capitalize(),
                                             lambda a, b, s: a.capitalize() + s + b.capitalize(),
                                             lambda a, b, s: a.upper() + s + b.upper()]:
                                c = combo_fn(self.keywords[i], self.keywords[j], sep)
                                if not seen.contains(c):
                                    seen.put(c, True)
                                    multi.append(c)
                            for suf in ['', '1', '123', '!', '@', '#', '2025', '2026']:
                                for combo_fn in [lambda a, b, s: a + b + s,
                                                 lambda a, b, s: a.capitalize() + b.capitalize() + s]:
                                    c = combo_fn(self.keywords[i], self.keywords[j], suf)
                                    if not seen.contains(c):
                                        seen.put(c, True)
                                        multi.append(c)
        combo_q = Queue()
        for m in multi:
            combo_q.enqueue(m)
        return combo_q, mutations

    def filter_wordlist(self, words):
        combo_mutations, single_mutations = self._generate_keyword_mutations()
        priority = Queue()
        remaining = Queue()
        seen = HashMap()

        combo_list = combo_mutations.to_list()
        for w in combo_list:
            if not seen.contains(w):
                seen.put(w, True)
                priority.enqueue(w)

        single_list = single_mutations.to_list()
        for w in single_list:
            if not seen.contains(w):
                seen.put(w, True)
                priority.enqueue(w)

        for word in words:
            if seen.contains(word):
                continue
            word_lower = word.lower()
            word_stripped = self._strip_specials(word)
            matched = False
            for kw in self.keywords:
                if kw in word_lower or kw in word_stripped:
                    matched = True
                    break
            if matched:
                seen.put(word, True)
                priority.enqueue(word)
            else:
                remaining.enqueue(word)
        return priority, remaining


# =============================================================================
# ATTACK MODULES
# =============================================================================

class AttackResult:
    def __init__(self):
        self.found = False
        self.password = None
        self.attempts = 0
        self.elapsed = 0.0
        self.speed = 0.0
        self.method = ""


class WordlistAttack:
    def __init__(self, callback=None):
        self.callback = callback
        self.stopped = False

    def crack_hash(self, target_hash, algo, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "Wordlist Attack"
        start = time.time()
        try:
            words = []
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    w = line.strip()
                    if w:
                        words.append(w)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        if keyword_filter and keyword_filter.keywords:
            priority_q, remaining_q = keyword_filter.filter_wordlist(words)
            ordered_words = priority_q.to_list() + remaining_q.to_list()
        else:
            ordered_words = words

        total = len(ordered_words)
        for i, word in enumerate(ordered_words):
            if self.stopped:
                break
            computed = HashEngine.compute(word, algo)
            result.attempts += 1
            if computed == target_hash.lower().strip():
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                return result
            if self.callback and result.attempts % 500 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class BruteForceAttack:
    def __init__(self, callback=None):
        self.callback = callback
        self.stopped = False

    def crack_hash(self, target_hash, algo, charset, min_len, max_len):
        result = AttackResult()
        result.method = "Brute Force Attack"
        start = time.time()
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                if self.stopped:
                    result.elapsed = time.time() - start
                    result.speed = result.attempts / max(result.elapsed, 0.001)
                    return result
                word = ''.join(combo)
                computed = HashEngine.compute(word, algo)
                result.attempts += 1
                if computed == target_hash.lower().strip():
                    result.found = True
                    result.password = word
                    result.elapsed = time.time() - start
                    result.speed = result.attempts / max(result.elapsed, 0.001)
                    if self.callback:
                        self.callback(result.attempts, 0, word, True)
                    return result
                if self.callback and result.attempts % 1000 == 0:
                    self.callback(result.attempts, 0, word, False)
        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class RuleBasedAttack:
    def __init__(self, callback=None):
        self.callback = callback
        self.stopped = False

    def generate_mutations(self, word):
        mutations = Queue()
        mutations.enqueue(word)
        mutations.enqueue(word.upper())
        mutations.enqueue(word.lower())
        mutations.enqueue(word.capitalize())
        mutations.enqueue(word.swapcase())
        mutations.enqueue(word[::-1])
        mutations.enqueue(word + word)
        leet_map = HashMap()
        leet_map.put('a', '@'); leet_map.put('e', '3'); leet_map.put('i', '1')
        leet_map.put('o', '0'); leet_map.put('s', '$'); leet_map.put('t', '7')
        leet_map.put('l', '1'); leet_map.put('g', '9'); leet_map.put('b', '8')
        leet = list(word.lower())
        for idx, ch in enumerate(leet):
            replacement = leet_map.get(ch)
            if replacement:
                leet[idx] = replacement
        mutations.enqueue(''.join(leet))
        suffixes = ['1', '12', '123', '1234', '!', '!!', '@', '#', '01', '99', '2024', '2025', '007', '69', '666']
        for s in suffixes:
            mutations.enqueue(word + s)
            mutations.enqueue(word.capitalize() + s)
        prefixes = ['!', '@', '#', '1', '123']
        for p in prefixes:
            mutations.enqueue(p + word)
        return mutations

    def crack_hash(self, target_hash, algo, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "Rule-Based Attack"
        start = time.time()
        try:
            words = []
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    w = line.strip()
                    if w:
                        words.append(w)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        if keyword_filter and keyword_filter.keywords:
            pq, rq = keyword_filter.filter_wordlist(words)
            ordered = pq.to_list() + rq.to_list()
        else:
            ordered = words

        total = len(ordered)
        for i, word in enumerate(ordered):
            if self.stopped:
                break
            mutations = self.generate_mutations(word)
            while not mutations.is_empty():
                if self.stopped:
                    break
                mutant = mutations.dequeue()
                computed = HashEngine.compute(mutant, algo)
                result.attempts += 1
                if computed == target_hash.lower().strip():
                    result.found = True
                    result.password = mutant
                    result.elapsed = time.time() - start
                    result.speed = result.attempts / max(result.elapsed, 0.001)
                    if self.callback:
                        self.callback(i + 1, total, mutant, True)
                    return result
            if self.callback and (i + 1) % 100 == 0:
                self.callback(i + 1, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class ZipCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack(self, zip_path, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "ZIP File Crack"
        start = time.time()
        try:
            zf = zipfile.ZipFile(zip_path)
        except Exception as e:
            result.method = f"Error: {e}"
            return result
        try:
            words = []
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    w = line.strip()
                    if w:
                        words.append(w)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        priority_count = 0
        if keyword_filter and keyword_filter.keywords:
            pq, rq = keyword_filter.filter_wordlist(words)
            priority_list = pq.to_list()
            remaining_list = rq.to_list()
            priority_count = len(priority_list)
            ordered = priority_list + remaining_list
            self._log(f"[KEYWORD PRIORITY] {priority_count} words matched keywords, trying those FIRST")
            if priority_count <= 20:
                for pw in priority_list:
                    self._log(f"  >> Priority: {pw}")
        else:
            ordered = words

        import tempfile
        tmp_dir = tempfile.mkdtemp()

        total = len(ordered)
        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            if priority_count > 0 and i == priority_count:
                self._log(f"[KEYWORD PRIORITY] Done with priority words, now trying remaining {len(ordered) - priority_count} words...")
            try:
                zf.extractall(path=tmp_dir, pwd=word.encode('utf-8'))
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                zf.close()
                import shutil
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return result
            except (RuntimeError, zipfile.BadZipFile, Exception):
                pass
            if self.callback and result.attempts % 200 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        zf.close()
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return result

    def stop(self):
        self.stopped = True


class PDFCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack(self, pdf_path, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "PDF File Crack"
        start = time.time()
        try:
            import pikepdf
        except ImportError:
            result.method = "Error: pikepdf not installed (pip install pikepdf)"
            return result
        try:
            words = []
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    w = line.strip()
                    if w:
                        words.append(w)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        priority_count = 0
        if keyword_filter and keyword_filter.keywords:
            pq, rq = keyword_filter.filter_wordlist(words)
            priority_list = pq.to_list()
            remaining_list = rq.to_list()
            priority_count = len(priority_list)
            ordered = priority_list + remaining_list
            self._log(f"[KEYWORD PRIORITY] {priority_count} words matched keywords, trying those FIRST")
            if priority_count <= 20:
                for pw in priority_list:
                    self._log(f"  >> Priority: {pw}")
        else:
            ordered = words

        total = len(ordered)
        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            if priority_count > 0 and i == priority_count:
                self._log(f"[KEYWORD PRIORITY] Done with priority words, now trying remaining {len(ordered) - priority_count} words...")
            try:
                with pikepdf.open(pdf_path, password=word) as pdf:
                    result.found = True
                    result.password = word
                    result.elapsed = time.time() - start
                    result.speed = result.attempts / max(result.elapsed, 0.001)
                    if self.callback:
                        self.callback(result.attempts, total, word, True)
                    return result
            except Exception:
                pass
            if self.callback and result.attempts % 100 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


# =============================================================================
# HASH GENERATOR UTILITY
# =============================================================================

class HashGenerator:
    @staticmethod
    def generate(text, algo):
        return HashEngine.compute(text, algo)

    @staticmethod
    def generate_all(text):
        results = HashMap()
        for algo in HashEngine.supported_algorithms():
            results.put(algo, HashEngine.compute(text, algo))
        return results


# =============================================================================
# HISTORY LOG (uses custom queue)
# =============================================================================

class SessionLog:
    def __init__(self):
        self.log = Queue()

    def add(self, result):
        entry = {
            'time': time.strftime('%H:%M:%S'),
            'method': result.method,
            'found': result.found,
            'password': result.password if result.found else 'N/A',
            'attempts': result.attempts,
            'elapsed': f"{result.elapsed:.2f}s",
            'speed': f"{result.speed:.0f} pwd/s"
        }
        self.log.enqueue(entry)

    def get_all(self):
        return self.log.to_list()

    def clear(self):
        self.log = Queue()


# =============================================================================
# GUI APPLICATION
# =============================================================================

if not HAS_TK:
    class CrackVaultApp:
        def __init__(self):
            raise RuntimeError("tkinter is required for GUI. Install it or run on a system with tkinter.")
        def run(self):
            pass
else:
    class CrackVaultApp:
        BG = '#0a0e14'
        FG = '#d4d4d4'
        ACCENT = '#00bfff'
        GREEN = '#00e676'
        RED = '#ff5252'
        ORANGE = '#ffab40'
        YELLOW = '#ffd740'
        CARD_BG = '#131820'
        ENTRY_BG = '#1a2030'
        BTN_BG = '#00bfff'
        BTN_STOP = '#ff5252'
        BORDER = '#1e2a3a'
        MUTED = '#6b7b8d'

        def __init__(self):
            self.root = tk.Tk()
            self.root.title("CrackVault")
            self.root.geometry("1100x750")
            self.root.configure(bg=self.BG)
            self.root.minsize(950, 680)
            try:
                icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', 'icon.ico')
                if os.path.exists(icon_path):
                    self.root.iconbitmap(icon_path)
            except Exception:
                pass
            self.session_log = SessionLog()
            self.current_attack = None
            self.attack_thread = None
            self.keyword_filter = KeywordFilter()
            self._setup_styles()
            self._build_ui()

        def _setup_styles(self):
            self.style = ttk.Style()
            self.style.theme_use('clam')
            self.style.configure('TNotebook', background=self.BG, borderwidth=0)
            self.style.configure('TNotebook.Tab', background=self.CARD_BG, foreground=self.MUTED,
                                 padding=[20, 10], font=('Segoe UI', 10, 'bold'))
            self.style.map('TNotebook.Tab', background=[('selected', self.BG)],
                           foreground=[('selected', self.ACCENT)])
            self.style.configure('TFrame', background=self.BG)
            self.style.configure('Card.TFrame', background=self.CARD_BG)
            self.style.configure('TLabel', background=self.BG, foreground=self.FG, font=('Segoe UI', 10))
            self.style.configure('Card.TLabel', background=self.CARD_BG, foreground=self.FG, font=('Segoe UI', 10))
            self.style.configure('Muted.TLabel', background=self.CARD_BG, foreground=self.MUTED, font=('Segoe UI', 9))
            self.style.configure('Title.TLabel', background=self.BG, foreground=self.ACCENT,
                                 font=('Segoe UI', 24, 'bold'))
            self.style.configure('Subtitle.TLabel', background=self.BG, foreground=self.MUTED,
                                 font=('Segoe UI', 10))
            self.style.configure('Header.TLabel', background=self.CARD_BG, foreground=self.ACCENT,
                                 font=('Segoe UI', 11, 'bold'))
            self.style.configure('Action.TButton', background=self.BTN_BG, foreground='#000000',
                                 font=('Segoe UI', 10, 'bold'), borderwidth=0, padding=[16, 8])
            self.style.map('Action.TButton', background=[('active', '#33ccff')])
            self.style.configure('Stop.TButton', background=self.BTN_STOP, foreground='#ffffff',
                                 font=('Segoe UI', 10, 'bold'), borderwidth=0, padding=[16, 8])
            self.style.map('Stop.TButton', background=[('active', '#ff7777')])
            self.style.configure('Small.TButton', background=self.ENTRY_BG, foreground=self.ACCENT,
                                 font=('Segoe UI', 9), borderwidth=0, padding=[10, 5])
            self.style.map('Small.TButton', background=[('active', self.BORDER)])
            self.style.configure('TCombobox', fieldbackground=self.ENTRY_BG, background=self.ENTRY_BG,
                                 foreground=self.FG, font=('Consolas', 10))
            self.style.configure('Horizontal.TProgressbar', background=self.ACCENT, troughcolor=self.ENTRY_BG)

        def _build_ui(self):
            header = ttk.Frame(self.root)
            header.pack(fill='x', padx=20, pady=(15, 5))
            ttk.Label(header, text="CrackVault", style='Title.TLabel').pack(side='left')
            ttk.Label(header, text="v1.0  |  Password Cracker for Ethical Hacking",
                      style='Subtitle.TLabel').pack(side='left', padx=(15, 0), pady=(8, 0))

            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill='both', expand=True, padx=20, pady=(5, 0))

            self._build_hash_crack_tab()
            self._build_file_crack_tab()
            self._build_hash_gen_tab()
            self._build_hash_id_tab()
            self._build_history_tab()
            self._build_status_bar()

        def _card(self, parent, pad=15):
            f = tk.Frame(parent, bg=self.CARD_BG, bd=0, highlightthickness=1,
                         highlightbackground=self.BORDER, highlightcolor=self.BORDER)
            f.inner_pad = pad
            return f

        def _entry(self, parent, width=50):
            e = tk.Entry(parent, bg=self.ENTRY_BG, fg=self.FG, insertbackground=self.ACCENT,
                         font=('Consolas', 11), relief='flat', bd=8, width=width,
                         selectbackground=self.ACCENT, selectforeground='#000000')
            return e

        def _label(self, parent, text, style='Card.TLabel', **kw):
            return tk.Label(parent, text=text, bg=self.CARD_BG, fg=self.FG,
                            font=('Segoe UI', 10), **kw)

        def _header_label(self, parent, text):
            return tk.Label(parent, text=text, bg=self.CARD_BG, fg=self.ACCENT,
                            font=('Segoe UI', 11, 'bold'))

        def _muted_label(self, parent, text):
            return tk.Label(parent, text=text, bg=self.CARD_BG, fg=self.MUTED,
                            font=('Segoe UI', 9))

        def _output(self, parent, height=12):
            t = scrolledtext.ScrolledText(parent, bg='#0c1018', fg=self.GREEN,
                                           font=('Consolas', 10), relief='flat', bd=8,
                                           insertbackground=self.FG, height=height, wrap='word',
                                           selectbackground=self.ACCENT, selectforeground='#000000')
            return t

        def _action_btn(self, parent, text, command):
            return ttk.Button(parent, text=text, style='Action.TButton', command=command)

        def _stop_btn(self, parent, text, command):
            return ttk.Button(parent, text=text, style='Stop.TButton', command=command)

        # =====================================================================
        # TAB 1: HASH CRACKING
        # =====================================================================
        def _build_hash_crack_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  Hash Crack  ')

            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)

            row0 = tk.Frame(inner, bg=self.CARD_BG)
            row0.pack(fill='x', pady=(0, 8))
            self._header_label(row0, "Target Hash").pack(side='left')
            self.hash_entry = self._entry(row0, width=72)
            self.hash_entry.pack(side='left', padx=(15, 0), fill='x', expand=True)

            row1 = tk.Frame(inner, bg=self.CARD_BG)
            row1.pack(fill='x', pady=(0, 8))
            self._label(row1, "Algorithm").pack(side='left')
            self.algo_var = tk.StringVar(value='md5')
            ttk.Combobox(row1, textvariable=self.algo_var, state='readonly', width=14,
                         values=sorted(HashEngine.supported_algorithms())).pack(side='left', padx=(10, 30))
            self._label(row1, "Attack Mode").pack(side='left')
            self.attack_var = tk.StringVar(value='Wordlist')
            ttk.Combobox(row1, textvariable=self.attack_var, state='readonly', width=14,
                         values=['Wordlist', 'Brute Force', 'Rule-Based']).pack(side='left', padx=(10, 0))

            row2 = tk.Frame(inner, bg=self.CARD_BG)
            row2.pack(fill='x', pady=(0, 8))
            self._label(row2, "Wordlist").pack(side='left')
            self.wl_entry = self._entry(row2, width=52)
            self.wl_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            ttk.Button(row2, text="Browse", style='Small.TButton',
                       command=lambda: self._browse(self.wl_entry)).pack(side='left')

            row3 = tk.Frame(inner, bg=self.CARD_BG)
            row3.pack(fill='x', pady=(0, 8))
            self._label(row3, "Keywords").pack(side='left')
            self.kw_entry = self._entry(row3, width=40)
            self.kw_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            self._muted_label(row3, "words to try first (space or comma separated)").pack(side='left')

            row4 = tk.Frame(inner, bg=self.CARD_BG)
            row4.pack(fill='x')
            self._muted_label(row4, "Brute Force:").pack(side='left')
            self._label(row4, "Min Len").pack(side='left', padx=(10, 0))
            self.bf_min = tk.Spinbox(row4, from_=1, to=8, width=3, bg=self.ENTRY_BG, fg=self.FG,
                                     font=('Consolas', 10), relief='flat', bd=4)
            self.bf_min.pack(side='left', padx=5)
            self._label(row4, "Max Len").pack(side='left', padx=(10, 0))
            self.bf_max = tk.Spinbox(row4, from_=1, to=8, width=3, bg=self.ENTRY_BG, fg=self.FG,
                                     font=('Consolas', 10), relief='flat', bd=4)
            self.bf_max.delete(0, 'end'); self.bf_max.insert(0, '4')
            self.bf_max.pack(side='left', padx=5)
            self._label(row4, "Charset").pack(side='left', padx=(15, 0))
            self.charset_var = tk.StringVar(value='lowercase')
            ttk.Combobox(row4, textvariable=self.charset_var, state='readonly', width=16,
                         values=['lowercase', 'uppercase', 'digits', 'lowercase+digits',
                                 'all printable']).pack(side='left', padx=5)

            btn_row = tk.Frame(tab, bg=self.BG)
            btn_row.pack(fill='x', padx=8, pady=6)
            self._action_btn(btn_row, "  START CRACK  ", self._start_hash_crack).pack(side='left', padx=(0, 8))
            self._stop_btn(btn_row, "  STOP  ", self._stop_attack).pack(side='left')
            self.hash_speed_lbl = tk.Label(btn_row, text="", bg=self.BG, fg=self.GREEN,
                                            font=('Consolas', 10, 'bold'))
            self.hash_speed_lbl.pack(side='right', padx=10)

            self.progress_var = tk.DoubleVar()
            ttk.Progressbar(tab, variable=self.progress_var, maximum=100,
                            style='Horizontal.TProgressbar').pack(fill='x', padx=8, pady=(0, 6))

            self.hash_output = self._output(tab)
            self.hash_output.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # =====================================================================
        # TAB 2: FILE CRACKING
        # =====================================================================
        def _build_file_crack_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  File Crack  ')

            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)

            row0 = tk.Frame(inner, bg=self.CARD_BG)
            row0.pack(fill='x', pady=(0, 8))
            self._header_label(row0, "File Type").pack(side='left')
            self.file_type_var = tk.StringVar(value='ZIP')
            ttk.Combobox(row0, textvariable=self.file_type_var, state='readonly', width=8,
                         values=['ZIP', 'PDF']).pack(side='left', padx=15)
            self._muted_label(row0, "Cracks password-protected ZIP and PDF files").pack(side='left')

            row1 = tk.Frame(inner, bg=self.CARD_BG)
            row1.pack(fill='x', pady=(0, 8))
            self._label(row1, "Target File").pack(side='left')
            self.file_entry = self._entry(row1, width=55)
            self.file_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            ttk.Button(row1, text="Browse", style='Small.TButton',
                       command=lambda: self._browse(self.file_entry,
                                                    [('ZIP', '*.zip'), ('PDF', '*.pdf'), ('All', '*.*')])).pack(side='left')

            row2 = tk.Frame(inner, bg=self.CARD_BG)
            row2.pack(fill='x', pady=(0, 8))
            self._label(row2, "Wordlist").pack(side='left')
            self.file_wl_entry = self._entry(row2, width=55)
            self.file_wl_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            ttk.Button(row2, text="Browse", style='Small.TButton',
                       command=lambda: self._browse(self.file_wl_entry)).pack(side='left')

            row3 = tk.Frame(inner, bg=self.CARD_BG)
            row3.pack(fill='x')
            self._label(row3, "Keywords").pack(side='left')
            self.file_kw_entry = self._entry(row3, width=40)
            self.file_kw_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            self._muted_label(row3, "words to try first (space or comma separated)").pack(side='left')

            btn_row = tk.Frame(tab, bg=self.BG)
            btn_row.pack(fill='x', padx=8, pady=6)
            self._action_btn(btn_row, "  CRACK FILE  ", self._start_file_crack).pack(side='left', padx=(0, 8))
            self._stop_btn(btn_row, "  STOP  ", self._stop_attack).pack(side='left')
            self.file_speed_lbl = tk.Label(btn_row, text="", bg=self.BG, fg=self.GREEN,
                                            font=('Consolas', 10, 'bold'))
            self.file_speed_lbl.pack(side='right', padx=10)

            self.file_progress_var = tk.DoubleVar()
            ttk.Progressbar(tab, variable=self.file_progress_var, maximum=100,
                            style='Horizontal.TProgressbar').pack(fill='x', padx=8, pady=(0, 6))

            self.file_output = self._output(tab)
            self.file_output.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # =====================================================================
        # TAB 3: HASH GENERATOR
        # =====================================================================
        def _build_hash_gen_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  Hash Generator  ')

            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)

            self._header_label(inner, "Enter text to generate all hash types").pack(anchor='w')
            row = tk.Frame(inner, bg=self.CARD_BG)
            row.pack(fill='x', pady=(8, 0))
            self.gen_entry = self._entry(row, width=60)
            self.gen_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
            self._action_btn(row, "  GENERATE  ", self._generate_hashes).pack(side='left')

            self.gen_output = self._output(tab, height=20)
            self.gen_output.pack(fill='both', expand=True, padx=8, pady=(6, 8))

        # =====================================================================
        # TAB 4: HASH IDENTIFIER
        # =====================================================================
        def _build_hash_id_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  Identify Hash  ')

            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)

            self._header_label(inner, "Paste a hash to identify its algorithm").pack(anchor='w')
            row = tk.Frame(inner, bg=self.CARD_BG)
            row.pack(fill='x', pady=(8, 0))
            self.id_entry = self._entry(row, width=70)
            self.id_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
            self._action_btn(row, "  IDENTIFY  ", self._identify_hash).pack(side='left')

            self.id_output = self._output(tab, height=18)
            self.id_output.pack(fill='both', expand=True, padx=8, pady=(6, 8))

        # =====================================================================
        # TAB 5: SESSION HISTORY
        # =====================================================================
        def _build_history_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  History  ')

            btn_row = tk.Frame(tab, bg=self.BG)
            btn_row.pack(fill='x', padx=8, pady=(12, 6))
            self._action_btn(btn_row, "  REFRESH  ", self._refresh_history).pack(side='left', padx=(0, 8))
            self._stop_btn(btn_row, "  CLEAR ALL  ", self._clear_history).pack(side='left')
            self.history_count_lbl = tk.Label(btn_row, text="0 entries", bg=self.BG, fg=self.MUTED,
                                              font=('Segoe UI', 10))
            self.history_count_lbl.pack(side='right', padx=10)

            self.history_output = self._output(tab, height=22)
            self.history_output.pack(fill='both', expand=True, padx=8, pady=(0, 8))

            self._refresh_history()

        # =====================================================================
        # STATUS BAR
        # =====================================================================
        def _build_status_bar(self):
            bar = tk.Frame(self.root, bg=self.CARD_BG, height=32)
            bar.pack(fill='x', side='bottom')
            bar.pack_propagate(False)
            self.status_label = tk.Label(bar, text="Ready", bg=self.CARD_BG, fg=self.MUTED,
                                         font=('Segoe UI', 9))
            self.status_label.pack(side='left', padx=20, pady=6)
            self.status_right = tk.Label(bar, text="CrackVault v1.0", bg=self.CARD_BG, fg=self.BORDER,
                                          font=('Segoe UI', 9))
            self.status_right.pack(side='right', padx=20, pady=6)

        # =====================================================================
        # HELPERS
        # =====================================================================
        def _browse(self, entry, ftypes=None):
            if ftypes is None:
                ftypes = [('Text files', '*.txt'), ('All', '*.*')]
            path = filedialog.askopenfilename(filetypes=ftypes)
            if path:
                entry.delete(0, 'end')
                entry.insert(0, path)

        def _log(self, widget, text, clear=False):
            widget.config(state='normal')
            if clear:
                widget.delete('1.0', 'end')
            widget.insert('end', text + '\n')
            widget.see('end')
            widget.config(state='disabled')

        def _status(self, text):
            self.status_label.config(text=text)

        def _get_charset(self):
            cs = self.charset_var.get()
            if cs == 'lowercase': return string.ascii_lowercase
            elif cs == 'uppercase': return string.ascii_uppercase
            elif cs == 'digits': return string.digits
            elif cs == 'lowercase+digits': return string.ascii_lowercase + string.digits
            else: return string.ascii_lowercase + string.ascii_uppercase + string.digits + '!@#$%'

        def _hash_progress_cb(self, current, total, word, found):
            if total > 0:
                self.progress_var.set((current / total) * 100)
            self.root.after(0, lambda: self._status(f"Trying: {word}  |  Attempts: {current:,}"))

        def _file_progress_cb(self, current, total, word, found):
            if total > 0:
                self.file_progress_var.set((current / total) * 100)
            self.root.after(0, lambda: self._status(f"Trying: {word}  |  Attempts: {current:,}"))

        # =====================================================================
        # ACTIONS
        # =====================================================================
        def _start_hash_crack(self):
            target = self.hash_entry.get().strip()
            if not target:
                messagebox.showwarning("CrackVault", "Enter a target hash.")
                return
            algo = self.algo_var.get()
            mode = self.attack_var.get()
            kw_text = self.kw_entry.get().strip()
            if kw_text:
                self.keyword_filter.set_keywords(kw_text)
            else:
                self.keyword_filter = KeywordFilter()

            self._log(self.hash_output, "", clear=True)
            self._log(self.hash_output, f"  CrackVault  -  {mode}")
            self._log(self.hash_output, f"  Algorithm    : {algo}")
            self._log(self.hash_output, f"  Target       : {target[:50]}{'...' if len(target) > 50 else ''}")
            if kw_text:
                self._log(self.hash_output, f"  Keywords     : {kw_text}")
            self._log(self.hash_output, f"{'_' * 60}\n")
            self.progress_var.set(0)
            self.hash_speed_lbl.config(text="")

            def run():
                if mode == 'Wordlist':
                    wl = self.wl_entry.get().strip()
                    if not wl:
                        self.root.after(0, lambda: messagebox.showwarning("CrackVault", "Select a wordlist file."))
                        return
                    attack = WordlistAttack(callback=self._hash_progress_cb)
                    self.current_attack = attack
                    result = attack.crack_hash(target, algo, wl, self.keyword_filter)
                elif mode == 'Brute Force':
                    charset = self._get_charset()
                    mn, mx = int(self.bf_min.get()), int(self.bf_max.get())
                    attack = BruteForceAttack(callback=self._hash_progress_cb)
                    self.current_attack = attack
                    result = attack.crack_hash(target, algo, charset, mn, mx)
                else:
                    wl = self.wl_entry.get().strip()
                    if not wl:
                        self.root.after(0, lambda: messagebox.showwarning("CrackVault", "Select a wordlist file."))
                        return
                    attack = RuleBasedAttack(callback=self._hash_progress_cb)
                    self.current_attack = attack
                    result = attack.crack_hash(target, algo, wl, self.keyword_filter)

                self.session_log.add(result)
                self.root.after(0, lambda: self._show_result(result, self.hash_output, self.hash_speed_lbl))

            self.attack_thread = threading.Thread(target=run, daemon=True)
            self.attack_thread.start()
            self._status("Cracking...")

        def _start_file_crack(self):
            file_path = self.file_entry.get().strip()
            wl = self.file_wl_entry.get().strip()
            if not file_path or not wl:
                messagebox.showwarning("CrackVault", "Select both a target file and wordlist.")
                return
            ftype = self.file_type_var.get()
            kw_text = self.file_kw_entry.get().strip()
            kw_filter = KeywordFilter()
            if kw_text:
                kw_filter.set_keywords(kw_text)

            self._log(self.file_output, "", clear=True)
            self._log(self.file_output, f"  CrackVault  -  {ftype} File Crack")
            self._log(self.file_output, f"  File         : {os.path.basename(file_path)}")
            self._log(self.file_output, f"  Wordlist     : {os.path.basename(wl)}")
            if kw_text:
                self._log(self.file_output, f"  Keywords     : {kw_text}")
            self._log(self.file_output, f"{'_' * 60}\n")
            self.file_progress_var.set(0)
            self.file_speed_lbl.config(text="")

            def run():
                def file_log(msg):
                    self.root.after(0, lambda m=msg: self._log(self.file_output, m))

                if ftype == 'ZIP':
                    attack = ZipCracker(callback=self._file_progress_cb, log_callback=file_log)
                else:
                    attack = PDFCracker(callback=self._file_progress_cb, log_callback=file_log)
                self.current_attack = attack
                result = attack.crack(file_path, wl, kw_filter)
                self.session_log.add(result)
                self.root.after(0, lambda: self._show_result(result, self.file_output, self.file_speed_lbl))

            self.attack_thread = threading.Thread(target=run, daemon=True)
            self.attack_thread.start()
            self._status("Cracking file...")

        def _show_result(self, result, output, speed_label):
            self._log(output, f"\n{'=' * 60}")
            if result.found:
                self._log(output, f"  PASSWORD FOUND:  {result.password}")
                self._log(output, f"  {'=' * 56}")
            else:
                self._log(output, f"  PASSWORD NOT FOUND")
            self._log(output, f"  Method   : {result.method}")
            self._log(output, f"  Attempts : {result.attempts:,}")
            self._log(output, f"  Time     : {result.elapsed:.3f} seconds")
            self._log(output, f"  Speed    : {result.speed:,.0f} passwords/sec")
            self._log(output, f"{'=' * 60}")
            if result.found:
                self._status(f"CRACKED: {result.password}")
                speed_label.config(text=f"{result.speed:,.0f} pwd/s  |  {result.attempts:,} attempts")
            else:
                self._status("Not found. Try a larger wordlist or different attack mode.")
                speed_label.config(text="")
            self.progress_var.set(100 if result.found else 0)
            self.file_progress_var.set(100 if result.found else 0)

        def _stop_attack(self):
            if self.current_attack:
                self.current_attack.stop()
                self._status("Stopped by user.")

        def _generate_hashes(self):
            text = self.gen_entry.get().strip()
            if not text:
                messagebox.showwarning("CrackVault", "Enter text to hash.")
                return
            results = HashGenerator.generate_all(text)
            self._log(self.gen_output, f"  Hashes for: '{text}'\n{'=' * 60}", clear=True)
            for algo, h in sorted(results.items()):
                self._log(self.gen_output, f"  {algo:12s}  {h}")
            self._log(self.gen_output, f"{'=' * 60}")

        def _identify_hash(self):
            h = self.id_entry.get().strip()
            if not h:
                messagebox.showwarning("CrackVault", "Paste a hash to identify.")
                return
            matches = HashEngine.identify_hash(h)
            self._log(self.id_output, f"  Hash   : {h}\n  Length : {len(h)} characters\n{'=' * 60}", clear=True)
            if matches:
                self._log(self.id_output, "  Possible algorithms:")
                for m in matches:
                    self._log(self.id_output, f"    ->  {m}")
            else:
                self._log(self.id_output, "  No matching algorithm found for this hash length.")
            self._log(self.id_output, f"{'=' * 60}")

        def _refresh_history(self):
            entries = self.session_log.get_all()
            self.history_count_lbl.config(text=f"{len(entries)} entries")
            self._log(self.history_output, f"  Session History\n{'=' * 60}", clear=True)
            if not entries:
                self._log(self.history_output, "  No history yet. Start cracking!")
            else:
                for i, e in enumerate(entries, 1):
                    status = "CRACKED" if e['found'] else "FAILED"
                    color_tag = 'found' if e['found'] else 'fail'
                    self._log(self.history_output,
                              f"  [{e['time']}]  {status:8s}  |  {e['method']:20s}  |  "
                              f"Password: {e['password']:16s}  |  {e['attempts']} attempts  |  "
                              f"{e['elapsed']}  |  {e['speed']}")
            self._log(self.history_output, f"{'=' * 60}")

        def _clear_history(self):
            if messagebox.askyesno("CrackVault", "Clear all session history?"):
                self.session_log.clear()
                self._refresh_history()
                self._status("History cleared.")

        def run(self):
            self.root.mainloop()


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    app = CrackVaultApp()
    app.run()
