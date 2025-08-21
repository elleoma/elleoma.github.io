#!/bin/bash

# Script to sync with upstream and translate new content

echo "🔄 Syncing with upstream repository..."

# Fetch upstream changes
git fetch upstream

# Check what's new
echo "📋 New commits in upstream:"
git log HEAD..upstream/main --oneline

# Merge upstream changes
git merge upstream/main

echo "🔍 Looking for new or modified markdown files..."

# Find files modified in the last merge
NEW_FILES=$(git diff --name-only HEAD~1 HEAD | grep '\.md$' || true)

if [ ! -z "$NEW_FILES" ]; then
    echo "📝 Found new/modified files to translate:"
    echo "$NEW_FILES"
    
    echo "🤖 Running translation on new content..."
    python3 scripts/translate_gitbook.py --only $NEW_FILES
    
    echo "✅ Translation completed for new content"
    echo "👀 Please review the changes and commit them"
else
    echo "✅ No new markdown files to translate"
fi
