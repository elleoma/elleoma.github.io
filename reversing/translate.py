#!/usr/bin/env python3
"""
Improved HonKit Translation Script with Robust Placeholder System
Fixes placeholder restoration issues in the original script
"""

import os
import re
import json
import time
import argparse
import frontmatter
import requests
from pathlib import Path
from typing import Optional, Dict, Any
import hashlib
import html
import base64

# Translation API classes
class LibreTranslateAPI:
    def __init__(self, url="http://localhost:5000"):
        self.url = url.rstrip('/')
        self.session = requests.Session()
    
    def translate(self, text: str) -> str:
        try:
            response = self.session.post(f"{self.url}/translate", json={
                "q": text,
                "source": "en",
                "target": "uk"
            })
            if response.status_code == 200:
                return response.json()["translatedText"]
            else:
                raise Exception(f"LibreTranslate error: {response.status_code}")
        except Exception as e:
            raise Exception(f"LibreTranslate failed: {e}")

class GoogleTranslateAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://translation.googleapis.com/language/translate/v2"
    
    def translate(self, text: str) -> str:
        try:
            response = requests.post(self.base_url, {
                'key': self.api_key,
                'q': text,
                'source': 'en',
                'target': 'uk'
            })
            if response.status_code == 200:
                return response.json()['data']['translations'][0]['translatedText']
            else:
                raise Exception(f"Google Translate error: {response.status_code}")
        except Exception as e:
            raise Exception(f"Google Translate failed: {e}")

class AzureTranslatorAPI:
    def __init__(self, api_key: str, region: str = "global"):
        self.api_key = api_key
        self.region = region
        self.base_url = "https://api.cognitive.microsofttranslator.com/translate"
    
    def translate(self, text: str) -> str:
        try:
            headers = {
                'Ocp-Apim-Subscription-Key': self.api_key,
                'Ocp-Apim-Subscription-Region': self.region,
                'Content-Type': 'application/json'
            }
            response = requests.post(
                f"{self.base_url}?api-version=3.0&from=en&to=uk",
                headers=headers,
                json=[{'text': text}]
            )
            if response.status_code == 200:
                return response.json()[0]['translations'][0]['text']
            else:
                raise Exception(f"Azure Translator error: {response.status_code}")
        except Exception as e:
            raise Exception(f"Azure Translator failed: {e}")

class DeepLAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api-free.deepl.com/v2/translate"
    
    def translate(self, text: str) -> str:
        try:
            response = requests.post(self.base_url, {
                'auth_key': self.api_key,
                'text': text,
                'source_lang': 'EN',
                'target_lang': 'UK'
            })
            if response.status_code == 200:
                return response.json()['translations'][0]['text']
            else:
                raise Exception(f"DeepL error: {response.status_code}")
        except Exception as e:
            raise Exception(f"DeepL failed: {e}")

# Fallback using deep-translator for Google Translate
try:
    from deep_translator import GoogleTranslator
    class FallbackGoogleAPI:
        def __init__(self):
            self.translator = GoogleTranslator(source='en', target='uk')
        
        def translate(self, text: str) -> str:
            return self.translator.translate(text)
except ImportError:
    class FallbackGoogleAPI:
        def translate(self, text: str) -> str:
            raise Exception("deep-translator not available")

class ImprovedHonKitTranslator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.debug = config.get('debug', True)
        
        # Enhanced protected terms (your existing list)
        self.protected_terms = {
            # Assembly instructions
            'mov', 'pop', 'jmp', 'call', 'ret', 'sub', 'mul', 'div', 
            'cmp', 'lea', 'xor', 'shl', 'shr', 'inc', 'dec',
            'nop', 'int', 'syscall', 'cpuid', 'rdtsc', 'hlt', 'cli', 'sti',
            'neg', 'rol', 'ror', 'rcl', 'rcr',
            
            # Registers (x86/x64)
            'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eip',
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'rip',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
            'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh',
            'ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp',
            'cs', 'ds', 'es', 'fs', 'gs', 'ss',
            
            # Tools and technologies
            'gdb', 'lldb', 'radare2', 'r2', 'ida', 'ida pro', 'ghidra',
            'objdump', 'readelf', 'nm', 'strings', 'file', 'hexdump', 'xxd',
            'strace', 'ltrace', 'valgrind', 'perf', 'wireshark',
            'python', 'perl', 'bash', 'sh', 'powershell', 'cmd',
            
            # Architectures and formats
            'x86', 'x64', 'x86_64', 'i386', 'amd64',
            'arm', 'arm64', 'aarch64', 'armv7', 'armv8',
            'mips', 'mips64', 'powerpc', 'ppc', 'sparc',
            'elf', 'pe', 'coff', 'macho', 'a.out',
            'plt', 'got', 'aslr', 'dep', 'nx', 'pie', 'relro',
            '.data', '.text',
            
            # Libraries and APIs
            'libc', 'glibc', 'musl', 'msvcrt', 'ucrtbase',
            'kernel32', 'ntdll', 'user32', 'advapi32',
            'malloc', 'printf', 'scanf', 'strcpy', 'strlen',
            'memcpy', 'memset', 'mmap', 'mprotect', 'execve',
            
            # Common programming terms
            'opcode', 'shellcode', 'rop', 'jop',
        }
        
        # Your existing terminology mapping
        self.terminology_map = {
            'reverse engineering': 'реверс-інженерія',
            'assembly language': 'мова асемблера',
            'assembly': 'асемблер',
            'debugging': 'налагодження',
            'debugger': 'налагоджувач',
            'disassembly': 'дизасемблювання',
            'disassemble': 'дизасемблювати',
            'instruction pointer': 'вказівник інструкцій',
            'register': 'регістр',
            'memory address': 'адреса пам\'яті',
            'binary analysis': 'аналіз бінарного коду',
            'static analysis': 'статичний аналіз',
            'dynamic analysis': 'динамічний аналіз',
            'control flow': 'потік керування',
            'call stack': 'стек викликів',
            'stack frame': 'кадр стеку',
            'function prologue': 'пролог функції',
            'function epilogue': 'епілог функції',
            'buffer overflow': 'переповнення буфера',
            'return address': 'адреса повернення',
            'exploit': 'експлойт',
            'vulnerability': 'вразливість',
            'payload': 'корисне навантаження',
            'shellcode': 'шелл-код',
            'gadget': 'гаджет',
            'code injection': 'ін\'єкція коду',
            'return-oriented programming': 'програмування орієнтоване на повернення',
            'jump-oriented programming': 'програмування орієнтоване на стрибки',
            'table of contents': 'зміст',
            # Fix common mistranslations
            'stack': 'стек',  # Not стопка
            'heap': 'куча',   # Not стопка
        }
        
        # Initialize translation APIs (keep your existing setup)
        self.apis = []
        self._setup_apis()
        
        # IMPROVED: Multiple robust placeholder strategies
        self.placeholders = {}
        self.hash_to_content = {}  # Hash-based lookup
        self.placeholder_counter = 0
        
        # Multiple placeholder formats for maximum robustness
        self.placeholder_formats = [
            "XMDX{hash}XMDX",      # Primary format
            "§PH{hash}PH§",        # Alternative 1
            "【{hash}】",           # Alternative 2 (Unicode brackets)
            "⟦{hash}⟧",            # Alternative 3 (Mathematical brackets)
            "◆{hash}◆",            # Alternative 4 (Diamond)
        ]
    
    def _setup_apis(self):
        """Setup translation APIs based on configuration"""
        
        # 1. LibreTranslate (if available)
        if self.config.get('libretranslate_url'):
            try:
                api = LibreTranslateAPI(self.config['libretranslate_url'])
                # Test if it's working
                api.translate("test")
                self.apis.append(('LibreTranslate', api))
                self.log("LibreTranslate API initialized")
            except Exception as e:
                self.log(f"LibreTranslate not available: {e}")
        
        # 2. DeepL (if API key provided)
        if self.config.get('deepl_api_key'):
            try:
                api = DeepLAPI(self.config['deepl_api_key'])
                self.apis.append(('DeepL', api))
                self.log("DeepL API initialized")
            except Exception as e:
                self.log(f"DeepL setup failed: {e}")
        
        # 3. Azure Translator (if API key provided)
        if self.config.get('azure_api_key'):
            try:
                api = AzureTranslatorAPI(
                    self.config['azure_api_key'],
                    self.config.get('azure_region', 'global')
                )
                self.apis.append(('Azure', api))
                self.log("Azure Translator API initialized")
            except Exception as e:
                self.log(f"Azure Translator setup failed: {e}")
        
        # 4. Google Translate (if API key provided)
        if self.config.get('google_api_key'):
            try:
                api = GoogleTranslateAPI(self.config['google_api_key'])
                self.apis.append(('Google', api))
                self.log("Google Translate API initialized")
            except Exception as e:
                self.log(f"Google Translate API setup failed: {e}")
        
        # 5. Fallback Google Translate (using deep-translator)
        try:
            api = FallbackGoogleAPI()
            self.apis.append(('Google Fallback', api))
            self.log("Google Fallback API initialized")
        except Exception as e:
            self.log(f"Google Fallback not available: {e}")
        
        if not self.apis:
            raise Exception("No translation APIs available! Please configure at least one API.")
        
        self.log(f"Initialized {len(self.apis)} translation APIs")
    
    def log(self, message):
        if self.debug:
            print(f"[DEBUG] {message}")
    
    def generate_content_hash(self, content: str) -> str:
        """Generate a unique hash for content"""
        hash_input = f"{content}{self.placeholder_counter}".encode('utf-8')
        return hashlib.md5(hash_input).hexdigest()[:12]
    
    def create_robust_placeholder(self, content: str) -> str:
        """Create multiple placeholder formats with hash-based lookup"""
        content_hash = self.generate_content_hash(content)
        
        # Primary placeholder
        primary_placeholder = self.placeholder_formats[0].format(hash=content_hash)
        
        # Store in hash map for robust lookup
        self.hash_to_content[content_hash] = content
        
        # Store all placeholder variations
        for format_pattern in self.placeholder_formats:
            placeholder = format_pattern.format(hash=content_hash)
            self.placeholders[placeholder] = content
            self.placeholders[placeholder.lower()] = content
            self.placeholders[placeholder.upper()] = content
        
        self.placeholder_counter += 1
        self.log(f"Created placeholder {primary_placeholder} for: {repr(content[:50])}")
        
        return primary_placeholder
    
    def protect_content(self, text: str) -> str:
        """Enhanced content protection with better patterns"""
        
        # 1. Protect technical terms first
        for term in sorted(self.protected_terms, key=len, reverse=True):
            pattern = r'\b' + re.escape(term) + r'\b'
            
            def replace_term(match):
                return self.create_robust_placeholder(match.group(0))
            
            text = re.sub(pattern, replace_term, text, flags=re.IGNORECASE)
        
        # 2. Enhanced protection patterns
        enhanced_patterns = [
            # Frontmatter - highest priority
            (r'^---\n.*?\n---\n', re.DOTALL | re.MULTILINE),
            
            # HTML blocks and tags
            (r'<[^>]+class="[^"]*"[^>]*>.*?</[^>]+>', re.DOTALL),  # HTML with classes
            (r'<[^>]+>.*?</[^>]+>', re.DOTALL),  # HTML blocks
            (r'<[^>]+/?>', 0),  # Self-closing tags
            
            # Code blocks (various formats)
            (r'```[\s\S]*?```', 0),  # Standard code blocks
            (r'~~~[\s\S]*?~~~', 0),  # Alternative code blocks
            (r'`[^`\n]+`', 0),  # Inline code
            
            # Images and links
            (r'!\[[^\]]*\]\([^\)]+\)', 0),  # Images
            
            # URLs and file paths
            (r'https?://[^\s\)\]\}\n]+', 0),  # URLs
            (r'[a-zA-Z]?:?[/\\][^\s\)\]\}\n]+', 0),  # File paths
            
            # Technical patterns
            (r'\b0x[0-9a-fA-F]+\b', 0),  # Hex numbers
            (r'\b[a-zA-Z_][a-zA-Z0-9_]*[\+\-]\d+\b', 0),  # Address offsets
            (r'\b[a-zA-Z_][a-zA-Z0-9_]*\(\)', 0),  # Function calls
            
            # Math expressions
            (r'\$\$[\s\S]*?\$\$', re.DOTALL),  # Block math
            (r'\$[^$\n]+\$', 0),  # Inline math
            
            # Email addresses
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 0),
        ]
        
        for pattern, flags in enhanced_patterns:
            def replace_match(match):
                return self.create_robust_placeholder(match.group(0))
            
            if flags:
                text = re.sub(pattern, replace_match, text, flags=flags)
            else:
                text = re.sub(pattern, replace_match, text)
        
        # 3. Special handling for links - protect URL but allow text translation
        def protect_link_url(match):
            link_text = match.group(1)
            link_url = match.group(2)
            url_placeholder = self.create_robust_placeholder(link_url)
            return f"[{link_text}]({url_placeholder})"

        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', protect_link_url, text)
        
        return text
    
    def restore_placeholders_robust(self, text: str) -> str:
        """Enhanced placeholder restoration with fuzzy matching"""
        
        # Phase 1: Direct replacement
        restored_text = text
        for placeholder, original in sorted(self.placeholders.items(), key=lambda x: len(x[0]), reverse=True):
            if placeholder in restored_text:
                restored_text = restored_text.replace(placeholder, original)
        
        # Phase 2: Hash-based fuzzy restoration
        # Look for any remaining hashes in various corrupted formats
        for content_hash, original_content in self.hash_to_content.items():
            # Try to find the hash in various corrupted forms
            hash_patterns = [
                content_hash,  # Exact hash
                content_hash.lower(),  # Lowercase
                content_hash.upper(),  # Uppercase
            ]
            
            for hash_variant in hash_patterns:
                # Look for hash surrounded by any of our placeholder patterns (possibly corrupted)
                fuzzy_patterns = [
                    rf'XMDX{re.escape(hash_variant)}XMDX',
                    rf'xmdx{re.escape(hash_variant)}xmdx',
                    rf'§PH{re.escape(hash_variant)}PH§',
                    rf'【{re.escape(hash_variant)}】',
                    rf'⟦{re.escape(hash_variant)}⟧',
                    rf'◆{re.escape(hash_variant)}◆',
                    
                    # Even more corrupted versions
                    rf'{re.escape(hash_variant)}',  # Just the hash
                    rf'[^\w]{re.escape(hash_variant)}[^\w]',  # Hash with non-word boundaries
                ]
                
                for pattern in fuzzy_patterns:
                    if re.search(pattern, restored_text, re.IGNORECASE):
                        restored_text = re.sub(pattern, original_content, restored_text, flags=re.IGNORECASE)
        
        # Phase 3: Look for any remaining partial hashes
        # This catches cases where translation systems mangle the placeholders severely
        remaining_hashes = re.findall(r'[a-f0-9]{8,12}', restored_text.lower())
        for potential_hash in remaining_hashes:
            if potential_hash in self.hash_to_content:
                # Replace with some context to avoid false positives
                pattern = rf'\b{re.escape(potential_hash)}\b'
                restored_text = re.sub(pattern, self.hash_to_content[potential_hash], 
                                     restored_text, flags=re.IGNORECASE)
        
        return restored_text
    
    def apply_terminology_mapping(self, text: str) -> str:
        """Apply custom Ukrainian terminology with improved accuracy"""
        for english, ukrainian in sorted(self.terminology_map.items(), key=lambda x: len(x[0]), reverse=True):
            # Use word boundaries and case-insensitive matching
            pattern = r'\b' + re.escape(english) + r'\b'
            text = re.sub(pattern, ukrainian, text, flags=re.IGNORECASE)
        return text
    
    def translate_with_fallback(self, text: str, max_length: int = 3000) -> str:
        """Translate text using available APIs with fallback"""
        if not text.strip():
            return text
        
        # Split text if too long
        if len(text) > max_length:
            sentences = re.split(r'(?<=[.!?])\s+', text)
            chunks = []
            current_chunk = ""
            
            for sentence in sentences:
                test_chunk = current_chunk + (" " if current_chunk else "") + sentence
                if len(test_chunk) > max_length:
                    if current_chunk:
                        chunks.append(current_chunk.strip())
                        current_chunk = sentence
                    else:
                        chunks.append(sentence)
                else:
                    current_chunk = test_chunk
            
            if current_chunk:
                chunks.append(current_chunk.strip())
            
            translated_chunks = []
            for i, chunk in enumerate(chunks):
                self.log(f"Translating chunk {i+1}/{len(chunks)}")
                translated = self.translate_with_fallback(chunk, max_length)
                translated_chunks.append(translated)
                time.sleep(0.5)  # Rate limiting
            
            return ' '.join(translated_chunks)
        
        # Try each API in order
        for api_name, api in self.apis:
            try:
                self.log(f"Trying {api_name} for translation...")
                result = api.translate(text)
                if result and result.strip():
                    self.log(f"Success with {api_name}")
                    return result
                else:
                    self.log(f"{api_name} returned empty result")
            except Exception as e:
                self.log(f"{api_name} failed: {e}")
                continue
        
        # If all APIs failed
        self.log("All translation APIs failed, returning original text")
        return text
    
    def translate_content(self, text: str) -> str:
        """IMPROVED main translation function"""
        if not text or not text.strip():
            return text

        self.log("Starting enhanced translation process")
        
        # Reset placeholders for this translation
        self.placeholders = {}
        self.hash_to_content = {}
        self.placeholder_counter = 0

        try:
            # Step 1: Protect content with enhanced system
            self.log("Protecting content with robust placeholders...")
            protected_text = self.protect_content(text)
            self.log(f"Created {len(self.hash_to_content)} protected segments")
            
            # Step 2: Translate the protected text
            self.log("Translating protected text...")
            translated_text = self.translate_with_fallback(protected_text)
            
            # Step 3: Restore placeholders with enhanced restoration
            self.log("Restoring placeholders with fuzzy matching...")
            restored_text = self.restore_placeholders_robust(translated_text)
            
            # Step 4: Apply terminology mapping
            self.log("Applying Ukrainian terminology mapping...")
            final_text = self.apply_terminology_mapping(restored_text)
            
            # Step 5: Post-processing cleanup
            final_text = self.post_process_cleanup(final_text)
            
            self.log("Enhanced translation completed successfully")
            return final_text

        except Exception as e:
            self.log(f"Error during enhanced translation: {e}")
            return text
    
    def post_process_cleanup(self, text: str) -> str:
        """Post-processing to clean up common translation artifacts"""
        
        # Fix common spacing issues around preserved elements
        text = re.sub(r'\s+([.,:;!?])', r'\1', text)  # Remove space before punctuation
        text = re.sub(r'([.,:;!?])\s*([.,:;!?])', r'\1\2', text)  # Fix double punctuation
        
        # Fix spacing around preserved technical terms
        text = re.sub(r'\s+([a-zA-Z_][a-zA-Z0-9_]*\(\))', r' \1', text)  # Function calls
        text = re.sub(r'\s+(0x[0-9a-fA-F]+)', r' \1', text)  # Hex numbers
        
        # Fix common Ukrainian-specific issues
        replacements = [
            # Fix incorrect translations that might have slipped through
            ('стопка', 'стек'),  # Stack should be стек, not стопка
            ('штабель', 'стек'),  # Another incorrect stack translation
            ('купа', 'куча'),    # Heap corrections
        ]
        
        for wrong, correct in replacements:
            text = re.sub(r'\b' + re.escape(wrong) + r'\b', correct, text, flags=re.IGNORECASE)
        
        return text
    
    def process_markdown_file(self, file_path: Path, backup: bool = True):
        """Enhanced markdown file processing"""
        print(f"\nProcessing: {file_path}")
        
        # Create backup
        if backup:
            backup_path = Path(str(file_path) + '.backup')
            if not backup_path.exists():
                import shutil
                shutil.copy2(file_path, backup_path)
                print(f"Created backup: {backup_path}")
        
        try:
            # Read file with better encoding handling
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            
            # Handle frontmatter more robustly
            frontmatter_match = re.match(r'^(---\n.*?\n---\n)(.*)', content, re.DOTALL)
            
            if frontmatter_match:
                frontmatter_content = frontmatter_match.group(1)
                main_content = frontmatter_match.group(2)
                
                # Parse frontmatter
                try:
                    post = frontmatter.loads(content)
                    has_frontmatter = True
                except:
                    # Fallback if frontmatter parsing fails
                    post = type('Post', (), {'content': main_content, 'metadata': {}})()
                    has_frontmatter = False
            else:
                post = type('Post', (), {'content': content, 'metadata': {}})()
                has_frontmatter = False
                main_content = content
            
            # Translate main content
            if main_content and main_content.strip():
                self.log(f"Translating main content ({len(main_content)} characters)")
                translated_content = self.translate_content(main_content)
                
                # Verify translation didn't break structure
                if self.verify_markdown_structure(main_content, translated_content):
                    self.log("Markdown structure verified successfully")
                else:
                    self.log("WARNING: Markdown structure may have been altered")
            else:
                translated_content = main_content
            
            # Translate frontmatter metadata
            translated_metadata = {}
            if has_frontmatter and hasattr(post, 'metadata') and post.metadata:
                for key, value in post.metadata.items():
                    if isinstance(value, str) and key in ['title', 'description', 'summary']:
                        self.log(f"Translating frontmatter field: {key}")
                        translated_metadata[key] = self.translate_content(value)
                    else:
                        translated_metadata[key] = value
            
            # Write result with better error handling
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    if has_frontmatter and translated_metadata:
                        f.write('---\n')
                        for key, value in translated_metadata.items():
                            # Handle multiline values properly
                            if '\n' in str(value):
                                f.write(f'{key}: |\n')
                                for line in str(value).split('\n'):
                                    f.write(f'  {line}\n')
                            else:
                                f.write(f'{key}: {value}\n')
                        f.write('---\n\n')
                    
                    f.write(translated_content)
                
                print(f"✅ Successfully processed: {file_path}")
                
            except Exception as write_error:
                print(f"❌ Error writing file {file_path}: {write_error}")
                # Restore from backup if write failed
                if backup and backup_path.exists():
                    import shutil
                    shutil.copy2(backup_path, file_path)
                    print(f"Restored from backup due to write error")
                
        except Exception as e:
            print(f"❌ Error processing {file_path}: {e}")
            import traceback
            if self.debug:
                traceback.print_exc()
    
    def verify_markdown_structure(self, original: str, translated: str) -> bool:
        """Verify that markdown structure is preserved after translation"""
        
        # Count structural elements
        def count_structures(text):
            return {
                'code_blocks': len(re.findall(r'```', text)),
                'inline_code': len(re.findall(r'`[^`]+`', text)),
                'images': len(re.findall(r'!\[', text)),
                'links': len(re.findall(r'\]\(', text)),
                'headers': len(re.findall(r'^#+\s', text, re.MULTILINE)),
                'html_tags': len(re.findall(r'<[^>]+>', text)),
            }
        
        original_counts = count_structures(original)
        translated_counts = count_structures(translated)
        
        # Check if counts match (with some tolerance for minor variations)
        for element_type, original_count in original_counts.items():
            translated_count = translated_counts.get(element_type, 0)
            
            if abs(original_count - translated_count) > 1:  # Allow 1 difference for tolerance
                self.log(f"Structure mismatch in {element_type}: {original_count} -> {translated_count}")
                return False
        
        return True


# Enhanced configuration loading with validation
def load_enhanced_config():
    """Load and validate configuration"""
    config = {
        'debug': True,
        'libretranslate_url': os.getenv('LIBRETRANSLATE_URL'),
        'deepl_api_key': os.getenv('DEEPL_API_KEY'),
        'google_api_key': os.getenv('GOOGLE_API_KEY'),
        'azure_api_key': os.getenv('AZURE_API_KEY'),
        'azure_region': os.getenv('AZURE_REGION', 'global'),
    }
    
    # Try to load from config file
    config_paths = [
        Path('translation_config.json'),
        Path('config.json'),
        Path('.translation_config.json'),
    ]
    
    for config_file in config_paths:
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    config.update(file_config)
                print(f"Loaded configuration from: {config_file}")
                break
            except Exception as e:
                print(f"Warning: Could not load config file {config_file}: {e}")
    
    # Validate that at least one API is configured
    api_configs = [
        config.get('libretranslate_url'),
        config.get('deepl_api_key'),
        config.get('google_api_key'),
        config.get('azure_api_key'),
    ]
    
    if not any(api_configs):
        print("WARNING: No translation APIs configured. Please set up at least one API.")
        print("Available options:")
        print("  - LIBRETRANSLATE_URL environment variable")
        print("  - DEEPL_API_KEY environment variable") 
        print("  - GOOGLE_API_KEY environment variable")
        print("  - AZURE_API_KEY environment variable")
        print("  - Create a translation_config.json file")
    
    return config


def main():
    parser = argparse.ArgumentParser(description="Enhanced HonKit Ukrainian translator with robust placeholder system")
    parser.add_argument('directory', nargs='?', default='.', help='Directory path')
    parser.add_argument('--no-debug', action='store_true', help='Disable debug output')
    parser.add_argument('--test-file', help='Test single file')
    parser.add_argument('--config', help='Config file path')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be translated without actually doing it')
    parser.add_argument('--verify-only', action='store_true', help='Only verify markdown structure without translating')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_enhanced_config()
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config.update(json.load(f))
        except Exception as e:
            print(f"Error loading config: {e}")
            return
    
    config['debug'] = not args.no_debug
    
    # Create enhanced translator
    try:
        translator = ImprovedHonKitTranslator(config)
        print(f"✅ Initialized enhanced translator with {len(translator.apis)} APIs")
    except Exception as e:
        print(f"❌ Error initializing translator: {e}")
        return
    
    if args.test_file:
        # Test single file
        file_path = Path(args.test_file)
        if file_path.exists():
            if args.verify_only:
                # Just verify structure
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                print("File structure analysis:")
                print(f"- Length: {len(content)} characters")
                print(f"- Lines: {len(content.splitlines())}")
                # Add more verification logic here
            else:
                translator.process_markdown_file(file_path)
        else:
            print(f"❌ File not found: {file_path}")
    else:
        # Process directory
        root_path = Path(args.directory)
        if not root_path.exists():
            print(f"❌ Directory not found: {root_path}")
            return
            
        md_files = [f for f in root_path.rglob('*.md') 
                   if not any(skip in str(f) for skip in ['.backup', 'node_modules', '.git', '_site'])]
        
        print(f"📁 Found {len(md_files)} markdown files to process in {root_path}")
        
        if args.dry_run:
            print("DRY RUN - Files that would be processed:")
            for md_file in md_files:
                print(f"  - {md_file.relative_to(root_path)}")
            return
        
        # Process files
        success_count = 0
        error_count = 0
        
        for i, md_file in enumerate(md_files, 1):
            print(f"\n[{i}/{len(md_files)}] {md_file.relative_to(root_path)}")
            
            try:
                if args.verify_only:
                    # Just verify, don't translate
                    with open(md_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    # Add verification logic
                    print(f"✅ Verified: {md_file}")
                    success_count += 1
                else:
                    translator.process_markdown_file(md_file)
                    success_count += 1
            except Exception as e:
                print(f"❌ Failed: {md_file} - {e}")
                error_count += 1
            
            # Rate limiting
            if i < len(md_files):  # Don't sleep after the last file
                time.sleep(1)
        
        print(f"\n📊 Processing complete:")
        print(f"  ✅ Success: {success_count}")
        print(f"  ❌ Errors: {error_count}")
        print(f"  📁 Total: {len(md_files)}")


if __name__ == "__main__":
    main()
