#!/usr/bin/env python3
"""
Robust HonKit Markdown Translation Script for Ukrainian
Uses multiple placeholder strategies and extensive debugging
Usage: python robust_translate.py [directory]
"""

import os
import re
import json
import time
import argparse
import frontmatter
from pathlib import Path
from deep_translator import DeeplTranslator, GoogleTranslator

class RobustHonKitTranslator:
    def __init__(self, use_deepl=True, debug=True):
        self.debug = debug
        
        # Technical terms that should NOT be translated
        self.protected_terms = {
            # Assembly instructions
            'mov', 'push', 'pop', 'jmp', 'call', 'ret', 'add', 'sub', 'mul', 'div',
            'cmp', 'test', 'lea', 'xor', 'and', 'or', 'not', 'shl', 'shr', 'inc', 'dec',
            'nop', 'int', 'syscall', 'cpuid', 'rdtsc', 'hlt', 'cli', 'sti',
            
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
            'strace', 'ltrace', 'valgrind', 'perf',
            'python', 'perl', 'bash', 'sh', 'powershell', 'cmd',
            
            # Architectures and formats
            'x86', 'x64', 'x86_64', 'i386', 'amd64',
            'arm', 'arm64', 'aarch64', 'armv7', 'armv8',
            'mips', 'mips64', 'powerpc', 'ppc', 'sparc',
            'elf', 'pe', 'coff', 'macho', 'a.out',
            'got', 'plt', 'aslr', 'dep', 'nx', 'pie', 'relro',
            
            # Libraries and APIs
            'libc', 'glibc', 'musl', 'msvcrt', 'ucrtbase',
            'kernel32', 'ntdll', 'user32', 'advapi32',
            'malloc', 'free', 'printf', 'scanf', 'strcpy', 'strlen',
            'memcpy', 'memset', 'mmap', 'mprotect', 'execve',
            
            # Additional RE-specific terms
            'main', 'unreachablefunction', 'hello world', 'ia32', 'ia-32',
            'breakpoint', 'nbsp', 'exit', 'debugger', 'disassemble',
            'disassembly', 'console', 'tutorial', 'hack', 'hacking',
        }
        
        # Ukrainian terminology mapping
        self.terminology_map = {
            'instruction pointer register': 'реєстр вказівника інструкцій',
            'instruction pointer': 'вказівник інструкцій',
            'reverse engineering': 'зворотна інженерія',
            'assembly language': 'мова асемблера',
            'debugging': 'налагодження',
            'debugger': 'налагоджувач',
            'function': 'функція',
            'register': 'регістр',
            'instruction': 'інструкція',
            'program': 'програма',
            'application': 'програма',
            'code': 'код',
            'memory': 'пам\'ять',
            'address': 'адреса',
            'pointer': 'вказівник',
            'control': 'контроль',
            'execute': 'виконувати',
            'execution': 'виконання',
            'complete control': 'повний контроль',
            'next instruction': 'наступна інструкція',
            'jump': 'перехід',
            'area': 'область',
            'table of contents': 'зміст',
            'lesson': 'урок',
            'lessons': 'уроки',
            'tutorial': 'підручник',
            'tutorial series': 'серія підручників',
            'example': 'приклад',
            'simple': 'простий',
            'detail': 'деталь',
            'functionality': 'функціональність',
            'called': 'називається',
            'never called': 'ніколи не викликається',
            'compile': 'компілювати',
            'compiled': 'скомпільований',
            'run': 'запускати',
            'running': 'виконання',
            'set': 'встановити',
            'examine': 'дослідити',
            'write down': 'записати',
            'step': 'крок',
            'next step': 'наступний крок',
            'continue': 'продовжити',
            'advantage': 'перевага',
            'hard work': 'наполеглива робота',
            'pay off': 'окупитися',
            'learn': 'вивчати',
            'hijack': 'перехопити',
            'disable': 'відключити',
            'trace': 'відстежити',
            'potential': 'потенційний',
            'originated': 'походити',
            'discussion': 'обговорення',
            'architecture': 'архітектура',
            'control registers': 'регістри керування',
        }
        
        # Initialize translator
        try:
            if use_deepl:
                self.translator = DeeplTranslator(source='en', target='uk')
            else:
                raise Exception("Using Google Translate as fallback")
        except:
            self.log("DeepL not available, using Google Translate...")
            self.translator = GoogleTranslator(source='en', target='uk')
        
        # Use multiple placeholder strategies
        self.placeholders = {}
        self.reverse_placeholders = {}  # For reverse lookup
        self.placeholder_counter = 0
        
        # Use a very unique pattern that won't be modified by translators
        # Using mixed case, numbers, and special chars
        self.placeholder_pattern = "XyZ9PlH{}ZuK8"
        
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
    
    def protect_content_comprehensive(self, text):
        """Comprehensive protection using multiple strategies"""
        
        # Strategy 1: Protect exact technical terms first
        for term in sorted(self.protected_terms, key=len, reverse=True):
            # Use very specific patterns to avoid over-matching
            if term.startswith('.') or term.startswith('0x'):
                pattern = re.escape(term)
            else:
                pattern = r'\b' + re.escape(term) + r'\b'
            
            def replace_match(match):
                placeholder = self.create_placeholder(match.group(0))
                return placeholder
            
            text = re.sub(pattern, replace_match, text, flags=re.IGNORECASE)
        
        # Strategy 2: Protect markdown and HTML structures
        patterns_to_protect = [
            # Frontmatter
            (r'^---\n.*?\n---\n', re.DOTALL | re.MULTILINE),
            # HTML tags with content
            (r'<[^>]+>.*?</[^>]+>', re.DOTALL),
            # Self-closing HTML tags
            (r'<[^>]+/>', 0),
            # Simple HTML tags
            (r'<[^>]+>', 0),
            # Images
            (r'!\[[^\]]*\]\([^\)]+\)', 0),
            # Code blocks
            (r'```[\s\S]*?```', 0),
            # Inline code
            (r'`[^`\n]+`', 0),
            # URLs
            (r'https?://[^\s\)\]\}]+', 0),
            # Hex addresses
            (r'\b0x[0-9a-fA-F]+\b', 0),
            # Email addresses
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 0),
            # HTML entities
            (r'&[a-zA-Z0-9]+;', 0),
            # Assembly references like main+17
            (r'\b[a-zA-Z_][a-zA-Z0-9_]*[\+\-]\d+\b', 0),
            # Function calls
            (r'\b[a-zA-Z_][a-zA-Z0-9_]*\(\)', 0),
            # Headers (markdown)
            (r'^(#{1,6})\s*', re.MULTILINE),
            # Lists
            (r'^(\d+\.|\*|\+|\-)\s', re.MULTILINE),
            # Blockquotes
            (r'^(>+)\s?', re.MULTILINE),
        ]
        
        for pattern, flags in patterns_to_protect:
            def replace_match(match):
                placeholder = self.create_placeholder(match.group(0))
                return placeholder
            
            if flags:
                text = re.sub(pattern, replace_match, text, flags=flags)
            else:
                text = re.sub(pattern, replace_match, text)
        
        # Strategy 3: Handle links specially - protect URL but allow text translation
        def protect_link_url(match):
            link_text = match.group(1)
            link_url = match.group(2)
            url_placeholder = self.create_placeholder(link_url)
            return f"[{link_text}]({url_placeholder})"

        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', protect_link_url, text)
        
        return text
    
    def restore_placeholders_robust(self, text):
        """Robust placeholder restoration with multiple strategies"""
        
        self.log(f"Starting restoration with {len(self.placeholders)} placeholders")
        self.log(f"Text length: {len(text)}")
        
        original_text = text
        
        # Strategy 1: Direct replacement (exact matches)
        sorted_placeholders = sorted(self.placeholders.items(), key=lambda x: len(x[0]), reverse=True)
        
        for placeholder, original in sorted_placeholders:
            if placeholder in text:
                text = text.replace(placeholder, original)
                self.log(f"Restored: {placeholder}")
        
        # Strategy 2: Case-insensitive search for mangled placeholders
        # Look for patterns that might be our placeholders with modified case
        placeholder_pattern_regex = r'xyz9plh(\d+)zuk8'
        
        def restore_mangled(match):
            # Extract the number and reconstruct the original placeholder
            number = match.group(1)
            possible_patterns = [
                f"XyZ9PlH{number}ZuK8",
                f"xyz9plh{number}zuk8", 
                f"XYZ9PLH{number}ZUK8",
            ]
            
            for pattern in possible_patterns:
                if pattern in self.placeholders:
                    self.log(f"Restored mangled placeholder: {match.group(0)} -> {pattern}")
                    return self.placeholders[pattern]
            
            # If not found, return as-is
            self.log(f"Could not restore mangled placeholder: {match.group(0)}")
            return match.group(0)
        
        text = re.sub(placeholder_pattern_regex, restore_mangled, text, flags=re.IGNORECASE)
        
        # Strategy 3: Find any remaining placeholder-like patterns and try to restore them
        remaining_patterns = re.findall(r'[a-zA-Z]*placeholder[a-zA-Z0-9_]*', text, re.IGNORECASE)
        
        if remaining_patterns:
            self.log(f"Found {len(remaining_patterns)} remaining placeholder-like patterns:")
            for pattern in remaining_patterns[:5]:  # Show first 5
                self.log(f"  {pattern}")
        
        # Final check - look for any of our placeholder components
        if 'placeholder' in text.lower():
            self.log("WARNING: Text still contains placeholder-like content!")
            
        restoration_success = len(original_text) != len(text) or original_text != text
        if restoration_success:
            self.log("Restoration made changes to text")
        else:
            self.log("No restorations performed - this might indicate a problem")
            
        return text
    
    def apply_terminology_mapping(self, text):
        """Apply custom Ukrainian terminology"""
        for english, ukrainian in sorted(self.terminology_map.items(), key=lambda x: len(x[0]), reverse=True):
            pattern = r'\b' + re.escape(english) + r'\b'
            text = re.sub(pattern, ukrainian, text, flags=re.IGNORECASE)
        return text
    
    def translate_text_chunk(self, text, max_length=3000):
        """Translate text with debugging"""
        if not text.strip():
            return text
        
        self.log(f"Translating chunk of {len(text)} characters")
        
        # Show what we're about to translate
        if self.debug:
            sample = text[:200].replace('\n', '\\n')
            self.log(f"Sample text to translate: {sample}...")
        
        try:
            if len(text) <= max_length:
                result = self.translator.translate(text)
                self.log(f"Translation completed, result length: {len(result) if result else 0}")
                return result if result else text
            else:
                # Split by sentences
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
                
                self.log(f"Split into {len(chunks)} chunks")
                
                translated_chunks = []
                for i, chunk in enumerate(chunks):
                    self.log(f"Translating chunk {i+1}/{len(chunks)}")
                    try:
                        translated = self.translator.translate(chunk)
                        translated_chunks.append(translated if translated else chunk)
                        time.sleep(1)  # Rate limiting
                    except Exception as e:
                        self.log(f"Error translating chunk {i+1}: {e}")
                        translated_chunks.append(chunk)
                
                return ' '.join(translated_chunks)
                
        except Exception as e:
            self.log(f"Translation error: {e}")
            return text
    
    def translate_content(self, text):
        """Main translation function with comprehensive debugging"""
        if not text or not text.strip():
            return text

        self.log("="*60)
        self.log("STARTING TRANSLATION PROCESS")
        self.log("="*60)
        
        # Reset placeholders
        self.placeholders = {}
        self.reverse_placeholders = {}
        self.placeholder_counter = 0

        try:
            self.log(f"Original text length: {len(text)} characters")
            
            # Step 1: Protect content
            self.log("STEP 1: Protecting content...")
            protected_text = self.protect_content_comprehensive(text)
            self.log(f"After protection: {len(protected_text)} characters")
            self.log(f"Created {len(self.placeholders)} unique placeholders")
            
            # Show sample of protected text
            if self.debug:
                sample = protected_text[:300].replace('\n', '\\n')
                self.log(f"Sample protected text: {sample}...")
            
            # Step 2: Translate
            self.log("STEP 2: Translating...")
            translated_text = self.translate_text_chunk(protected_text)
            
            if not translated_text:
                self.log("Translation returned empty result!")
                return text
            
            self.log(f"After translation: {len(translated_text)} characters")
            
            # Show sample of translated text (with placeholders)
            if self.debug:
                sample = translated_text[:300].replace('\n', '\\n')
                self.log(f"Sample translated text: {sample}...")
            
            # Step 3: Restore placeholders
            self.log("STEP 3: Restoring placeholders...")
            restored_text = self.restore_placeholders_robust(translated_text)
            self.log(f"After restoration: {len(restored_text)} characters")
            
            # Step 4: Apply terminology
            self.log("STEP 4: Applying terminology mapping...")
            final_text = self.apply_terminology_mapping(restored_text)
            self.log(f"Final text length: {len(final_text)} characters")
            
            # Final validation
            remaining_placeholders = []
            for placeholder in self.placeholders.keys():
                if placeholder.lower() in final_text.lower():
                    remaining_placeholders.append(placeholder)
            
            if remaining_placeholders:
                self.log(f"WARNING: {len(remaining_placeholders)} placeholders not restored!")
                for ph in remaining_placeholders[:3]:
                    self.log(f"  Remaining: {ph}")
                    
                # Try emergency restoration
                for ph in remaining_placeholders:
                    if ph in self.placeholders:
                        final_text = final_text.replace(ph, self.placeholders[ph])
                        final_text = final_text.replace(ph.lower(), self.placeholders[ph])
                        final_text = final_text.replace(ph.upper(), self.placeholders[ph])
            else:
                self.log("SUCCESS: All placeholders restored!")
            
            self.log("TRANSLATION PROCESS COMPLETED")
            self.log("="*60)
            
            return final_text

        except Exception as e:
            self.log(f"CRITICAL ERROR during translation: {e}")
            import traceback
            traceback.print_exc()
            
            # Emergency restoration attempt
            try:
                return self.restore_placeholders_robust(text)
            except:
                return text

    def process_markdown_file(self, file_path, backup=True):
        """Process a single markdown file with extensive logging"""
        print(f"\n{'='*80}")
        print(f"PROCESSING FILE: {file_path}")
        print(f"{'='*80}")
        
        # Create backup
        if backup:
            backup_path = Path(str(file_path) + '.backup')
            if not backup_path.exists():
                import shutil
                shutil.copy2(file_path, backup_path)
                print(f"Backup created: {backup_path}")
        
        try:
            # Read file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print(f"Original file size: {len(content)} characters")
            
            # Handle frontmatter
            has_frontmatter = content.startswith('---')
            if has_frontmatter:
                try:
                    post = frontmatter.loads(content)
                    print("Frontmatter detected and parsed")
                except:
                    post = type('Post', (), {'content': content, 'metadata': {}})()
                    has_frontmatter = False
                    print("Frontmatter parsing failed, treating as regular content")
            else:
                post = type('Post', (), {'content': content, 'metadata': {}})()
            
            # Translate main content
            if post.content.strip():
                print("Translating main content...")
                translated_content = self.translate_content(post.content)
                print(f"Translated content size: {len(translated_content)} characters")
            else:
                translated_content = post.content
                print("No content to translate")
            
            # Translate frontmatter
            translated_metadata = {}
            if has_frontmatter and hasattr(post, 'metadata') and post.metadata:
                print("Translating frontmatter...")
                for key, value in post.metadata.items():
                    if isinstance(value, str) and key in ['title', 'description', 'summary']:
                        print(f"  Translating {key}: {repr(value[:50])}...")
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
            
            print(f"✅ SUCCESS: File processed and saved")
            
        except Exception as e:
            print(f"❌ ERROR processing {file_path}: {e}")
            import traceback
            traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Robust HonKit Ukrainian translator")
    parser.add_argument('directory', nargs='?', default='.', help='Directory path')
    parser.add_argument('--use-google', action='store_true', help='Use Google Translate')
    parser.add_argument('--no-debug', action='store_true', help='Disable debug output')
    parser.add_argument('--test-file', help='Test single file')
    
    args = parser.parse_args()
    
    translator = RobustHonKitTranslator(
        use_deepl=not args.use_google,
        debug=not args.no_debug
    )
    
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
            print(f"\n[{i}/{len(md_files)}] Processing: {md_file.relative_to(root_path)}")
            translator.process_markdown_file(md_file)
            time.sleep(2)  # Rate limiting

if __name__ == "__main__":
    main()
