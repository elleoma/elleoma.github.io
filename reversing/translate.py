#!/usr/bin/env python3
"""
HonKit Markdown Translation Script for Ukrainian
Supports multiple translation APIs with fallbacks and optimization
Usage: python enhanced_translate.py [directory]
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

class EnhancedHonKitTranslator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.debug = config.get('debug', True)
        
        # Technical terms that should NOT be translated
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
            # 'buffer', 'stack', 'heap', 'pointer', 'offset',
            'opcode', 'shellcode', 'rop', 'jop',
        }
        
        # Ukrainian terminology mapping for better technical translation
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
        }
        
        # Initialize translation APIs
        self.apis = []
        self._setup_apis()
        
        # Use multiple placeholder strategies
        self.placeholders = {}
        self.reverse_placeholders = {}  # For reverse lookup
        self.placeholder_counter = 0
        
        # Use a very unique pattern that won't be modified by translators
        self.placeholder_pattern = "XyZ9PlH{}ZuK8"
    
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
    
    def create_placeholder(self, content):
        """Create a unique placeholder for protected content with multiple fallbacks"""
        # Create main placeholder
        placeholder = self.placeholder_pattern.format(self.placeholder_counter)
        
        # Store in both directions for robust lookup
        self.placeholders[placeholder] = content
        self.reverse_placeholders[content] = placeholder
        
        # Also store lowercase and case variations in case translator modifies case
        placeholder_lower = placeholder.lower()
        placeholder_upper = placeholder.upper()
        
        self.placeholders[placeholder_lower] = content
        self.placeholders[placeholder_upper] = content
        
        self.placeholder_counter += 1
        
        self.log(f"Created placeholder: {placeholder} for content: {repr(content[:50])}...")
        return placeholder
    
    def protect_content(self, text):
        """Protect technical content from translation"""
        
        # 1. Protect technical terms
        for term in sorted(self.protected_terms, key=len, reverse=True):
            pattern = r'\b' + re.escape(term) + r'\b'
            
            def replace_term(match):
                return self.create_placeholder(match.group(0))
            
            text = re.sub(pattern, replace_term, text, flags=re.IGNORECASE)
        
        # 2. Protect various content types
        patterns_to_protect = [
            # Frontmatter
            (r'^---\n.*?\n---\n', re.DOTALL | re.MULTILINE),
            # Code blocks
            (r'```[\s\S]*?```', 0),
            # Inline code
            (r'`[^`\n]+`', 0),
            # HTML tags
            (r'<[^>]+>.*?</[^>]+>', re.DOTALL),
            (r'<[^>]+/>', 0),
            (r'<[^>]+>', 0),
            # URLs
            (r'https?://[^\s\)\]\}]+', 0),
            # Images
            (r'!\[[^\]]*\]\([^\)]+\)', 0),
            # Hex addresses and numbers
            (r'\b0x[0-9a-fA-F]+\b', 0),
            # Assembly references like main+17
            (r'\b[a-zA-Z_][a-zA-Z0-9_]*[\+\-]\d+\b', 0),
            # Function calls
            (r'\b[a-zA-Z_][a-zA-Z0-9_]*\(\)', 0),
            # File paths
            (r'[a-zA-Z]?:?[/\\][^\s\)\]\}\n]+', 0),
            # Email addresses
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 0),
        ]
        
        for pattern, flags in patterns_to_protect:
            def replace_match(match):
                return self.create_placeholder(match.group(0))
            
            if flags:
                text = re.sub(pattern, replace_match, text, flags=flags)
            else:
                text = re.sub(pattern, replace_match, text)
        
        # 3. Handle links specially - protect URL but allow text translation
        def protect_link_url(match):
            link_text = match.group(1)
            link_url = match.group(2)
            url_placeholder = self.create_placeholder(link_url)
            return f"[{link_text}]({url_placeholder})"

        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', protect_link_url, text)
        
        return text
    
    def restore_placeholders(self, text):
        """Restore protected content"""
        for placeholder, original in sorted(self.placeholders.items(), key=lambda x: len(x[0]), reverse=True):
            text = text.replace(placeholder, original)
        return text
    
    def apply_terminology_mapping(self, text):
        """Apply custom Ukrainian terminology"""
        for english, ukrainian in sorted(self.terminology_map.items(), key=lambda x: len(x[0]), reverse=True):
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
        """Main translation function"""
        if not text or not text.strip():
            return text

        self.log("Starting translation process")
        
        # Reset placeholders
        self.placeholders = {}
        self.reverse_placeholders = {}
        self.placeholder_counter = 0

        try:
            # Step 1: Protect content
            self.log("Protecting technical content...")
            protected_text = self.protect_content(text)
            self.log(f"Created {len(self.placeholders)} placeholders")
            
            # Step 2: Translate
            self.log("Translating...")
            translated_text = self.translate_with_fallback(protected_text)
            
            # Step 3: Restore placeholders
            self.log("Restoring protected content...")
            restored_text = self.restore_placeholders(translated_text)
            
            # Step 4: Apply terminology mapping
            self.log("Applying terminology mapping...")
            final_text = self.apply_terminology_mapping(restored_text)
            
            self.log("Translation completed successfully")
            return final_text

        except Exception as e:
            self.log(f"Error during translation: {e}")
            return text
    
    def process_markdown_file(self, file_path: Path, backup: bool = True):
        """Process a single markdown file"""
        print(f"\nProcessing: {file_path}")
        
        # Create backup
        if backup:
            backup_path = Path(str(file_path) + '.backup')
            if not backup_path.exists():
                import shutil
                shutil.copy2(file_path, backup_path)
        
        try:
            # Read file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Handle frontmatter
            if content.startswith('---'):
                try:
                    post = frontmatter.loads(content)
                    has_frontmatter = True
                except:
                    post = type('Post', (), {'content': content, 'metadata': {}})()
                    has_frontmatter = False
            else:
                post = type('Post', (), {'content': content, 'metadata': {}})()
                has_frontmatter = False
            
            # Translate main content
            if post.content.strip():
                translated_content = self.translate_content(post.content)
            else:
                translated_content = post.content
            
            # Translate frontmatter
            translated_metadata = {}
            if has_frontmatter and hasattr(post, 'metadata') and post.metadata:
                for key, value in post.metadata.items():
                    if isinstance(value, str) and key in ['title', 'description', 'summary']:
                        translated_metadata[key] = self.translate_content(value)
                    else:
                        translated_metadata[key] = value
            
            # Write result
            with open(file_path, 'w', encoding='utf-8') as f:
                if has_frontmatter and translated_metadata:
                    f.write('---\n')
                    for key, value in translated_metadata.items():
                        f.write(f'{key}: {value}\n')
                    f.write('---\n\n')
                    f.write(translated_content)
                else:
                    f.write(translated_content)
            
            print(f"✅ Success: {file_path}")
            
        except Exception as e:
            print(f"❌ Error processing {file_path}: {e}")

def load_config():
    """Load configuration from file or environment variables"""
    config = {
        'debug': True,
        'libretranslate_url': os.getenv('LIBRETRANSLATE_URL'),
        'deepl_api_key': os.getenv('DEEPL_API_KEY'),
        'google_api_key': os.getenv('GOOGLE_API_KEY'),
        'azure_api_key': os.getenv('AZURE_API_KEY'),
        'azure_region': os.getenv('AZURE_REGION', 'global'),
    }
    
    # Try to load from config file
    config_file = Path('translation_config.json')
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    
    return config

def main():
    parser = argparse.ArgumentParser(description="Enhanced HonKit Ukrainian translator")
    parser.add_argument('directory', nargs='?', default='.', help='Directory path')
    parser.add_argument('--no-debug', action='store_true', help='Disable debug output')
    parser.add_argument('--test-file', help='Test single file')
    parser.add_argument('--config', help='Config file path')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config()
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config.update(json.load(f))
        except Exception as e:
            print(f"Error loading config: {e}")
            return
    
    config['debug'] = not args.no_debug
    
    # Create translator
    try:
        translator = EnhancedHonKitTranslator(config)
    except Exception as e:
        print(f"Error initializing translator: {e}")
        return
    
    if args.test_file:
        # Test single file
        file_path = Path(args.test_file)
        if file_path.exists():
            translator.process_markdown_file(file_path)
        else:
            print(f"File not found: {file_path}")
    else:
        # Process directory
        root_path = Path(args.directory)
        md_files = [f for f in root_path.rglob('*.md') 
                   if not any(skip in str(f) for skip in ['.backup', 'node_modules', '.git'])]
        
        print(f"Found {len(md_files)} markdown files to process")
        
        for i, md_file in enumerate(md_files, 1):
            print(f"\n[{i}/{len(md_files)}] {md_file.relative_to(root_path)}")
            translator.process_markdown_file(md_file)
            time.sleep(1)  # Rate limiting

if __name__ == "__main__":
    main()


