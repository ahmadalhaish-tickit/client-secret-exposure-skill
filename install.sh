#!/bin/bash
# One-line install for the nextjs-secret-exposure Claude skill

SKILLS_DIR="$HOME/.claude/skills/nextjs-secret-exposure"

if [ -d "$SKILLS_DIR" ]; then
  echo "Updating existing skill..."
  git -C "$SKILLS_DIR" pull
else
  echo "Installing nextjs-secret-exposure skill..."
  git clone https://github.com/ahmadalhaish-tickit/nextjs-secret-exposure-skill "$SKILLS_DIR"
fi

echo "Done. Skill installed at: $SKILLS_DIR"
