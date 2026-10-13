#!/usr/bin/env bash
# ==============================================================================
# Conventional Commits 规范化提交助手 (支持交互式与非交互式/AI自动化调用)
#
# 引导开发者或自动化脚本按规范组装提交信息，提供变更预览、类型校验与一键推送。
#
# @author Ateng
# @since 2026-10-13
# ==============================================================================

set -eo pipefail

# 终端色彩定义（在支持的终端下提供视觉区分，兼容非 TTY 降级）
if [ -t 1 ]; then
  COLOR_RESET="\033[0m"
  COLOR_BOLD="\033[1m"
  COLOR_GREEN="\033[32m"
  COLOR_BLUE="\033[34m"
  COLOR_YELLOW="\033[33m"
  COLOR_RED="\033[31m"
  COLOR_CYAN="\033[36m"
else
  COLOR_RESET=""
  COLOR_BOLD=""
  COLOR_GREEN=""
  COLOR_BLUE=""
  COLOR_YELLOW=""
  COLOR_RED=""
  COLOR_CYAN=""
fi

log_info() {
  printf "%b[INFO]%b %s\n" "${COLOR_BLUE}" "${COLOR_RESET}" "$1"
}

log_success() {
  printf "%b[SUCCESS]%b %s\n" "${COLOR_GREEN}" "${COLOR_RESET}" "$1"
}

log_warn() {
  printf "%b[WARN]%b %s\n" "${COLOR_YELLOW}" "${COLOR_RESET}" "$1"
}

log_error() {
  printf "%b[ERROR]%b %s\n" "${COLOR_RED}" "${COLOR_RESET}" "$1"
}

# ==============================================================================
# 1. 命令行参数解析 (支持非交互式调用)
# ==============================================================================
CLI_TYPE=""
CLI_SCOPE=""
CLI_MSG=""
CLI_BREAKING=false
CLI_STAGE_ALL=false
CLI_PUSH=false
AUTO_CONFIRM=false
IS_NON_INTERACTIVE=false

show_help() {
  printf "%b\n" "用法: bash scripts/commit.sh [选项]"
  printf "%b\n" ""
  printf "%b\n" "选项说明 (支持交互向导与非交互式/AI自动化调用):"
  printf "%b\n" "  -t, --type <type>       提交类型 (feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
  printf "%b\n" "  -s, --scope <scope>     可选影响范围 (如 core, cli, tools)"
  printf "%b\n" "  -m, --message <msg>     提交描述 (必填，简明扼要)"
  printf "%b\n" "  -b, --breaking          标记为破坏性更新 (Breaking Changes，自动追加 !)"
  printf "%b\n" "  -a, --all               自动暂存全部变动 (注意: 相当于 git add -A，请谨慎使用)"
  printf "%b\n" "  -p, --push              提交成功后自动推送到当前分支远程仓库"
  printf "%b\n" "  -y, --yes               跳过确认提示，直接执行提交"
  printf "%b\n" "  -h, --help              显示帮助信息"
  printf "%b\n" ""
  printf "%b\n" "无参数运行示例 (交互向导模式):"
  printf "%b\n" "  bash scripts/commit.sh"
  printf "%b\n" ""
  printf "%b\n" "非交互式调用示例 (推荐先精准 git add，再调用提交助手):"
  printf "%b\n" "  git add <file-path>"
  printf "%b\n" "  bash scripts/commit.sh -t feat -s core -m \"实现新功能\" -p -y"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -t|--type)
      CLI_TYPE="$2"
      IS_NON_INTERACTIVE=true
      shift 2
      ;;
    -s|--scope)
      CLI_SCOPE="$2"
      shift 2
      ;;
    -m|--message)
      CLI_MSG="$2"
      IS_NON_INTERACTIVE=true
      shift 2
      ;;
    -b|--breaking)
      CLI_BREAKING=true
      shift
      ;;
    -a|--all)
      CLI_STAGE_ALL=true
      shift
      ;;
    -p|--push)
      CLI_PUSH=true
      shift
      ;;
    -y|--yes)
      AUTO_CONFIRM=true
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      log_error "未知参数: $1 (使用 -h 或 --help 查看支持的选项)"
      exit 1
      ;;
  esac
done

# ==============================================================================
# 2. 基础环境与工作区自检
# ==============================================================================
if ! command -v git >/dev/null 2>&1; then
  log_error "未检测到 git 命令，请先安装 Git。"
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  log_error "当前目录不在 Git 仓库内，请在 Git 仓库内执行。"
  exit 1
fi

# 自动定位并切换至仓库根目录，支持在任意子目录下执行
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

# 自动检测并注册本地 Git 提交规范钩子 (自愈机制)
if [ -d ".githooks" ] && [ "$(git config core.hooksPath 2>/dev/null || echo '')" != ".githooks" ]; then
  chmod +x .githooks/* 2>/dev/null || true
  git config core.hooksPath .githooks 2>/dev/null || true
fi

# 检查 Git 提交者配置
GIT_USER=$(git config user.name 2>/dev/null || echo "")
GIT_EMAIL=$(git config user.email 2>/dev/null || echo "")
if [ -z "$GIT_USER" ] || [ -z "$GIT_EMAIL" ]; then
  log_error "未检测到 Git 用户身份配置！请先设置:"
  printf "  git config user.name \"Your Name\"\n"
  printf "  git config user.email \"you@example.com\"\n"
  exit 1
fi

STATUS_OUTPUT=$(git status --porcelain)
if [ -z "$STATUS_OUTPUT" ]; then
  log_warn "当前工作区没有任何修改或未跟踪的文件，无需提交。"
  exit 0
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

# ==============================================================================
# 3. 暂存区检查与智能暂存 (先确认变动再撰写信息)
# ==============================================================================
if [ "$CLI_STAGE_ALL" = true ]; then
  log_info "正在自动暂存当前所有改动 (git add -A)..."
  git add -A
elif [ "$IS_NON_INTERACTIVE" = false ]; then
  printf "\n%b\n" "${COLOR_BOLD}${COLOR_CYAN}================================================================${COLOR_RESET}"
  printf "%b\n" "${COLOR_BOLD}${COLOR_CYAN}         Conventional Commits 规范化提交助手                     ${COLOR_RESET}"
  printf "%b\n" "${COLOR_BOLD}${COLOR_CYAN}================================================================${COLOR_RESET}"
  printf "当前工作分支: %b\n\n" "${COLOR_GREEN}${CURRENT_BRANCH}${COLOR_RESET}"

  printf "%b当前文件变更概览 (git status):%b\n" "${COLOR_BOLD}" "${COLOR_RESET}"
  git status --short
  printf "\n"

  if git diff --cached --quiet; then
    # 暂存区无内容，但工作区有改动
    printf "%b当前暂存区 (Staged) 无内容。是否暂存当前所有改动 (git add -A)? [Y/n]: %b" "${COLOR_BOLD}" "${COLOR_RESET}"
    read -r STAGE_ALL_CHOICE
    STAGE_ALL_CHOICE=$(echo "$STAGE_ALL_CHOICE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$STAGE_ALL_CHOICE" in
      [nN][oO]|[nN])
        log_warn "暂存区为空且未暂存改动，终止提交。"
        exit 0
        ;;
      *)
        log_info "正在暂存全部变动 (git add -A)..."
        git add -A
        ;;
    esac
  else
    # 暂存区已有内容
    log_info "检测到暂存区已有文件已暂存。"
    printf "%b是否仅提交已暂存的变动? (选 n 则追加暂存全部变动) [Y/n]: %b" "${COLOR_BOLD}" "${COLOR_RESET}"
    read -r ONLY_STAGED_CHOICE
    ONLY_STAGED_CHOICE=$(echo "$ONLY_STAGED_CHOICE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$ONLY_STAGED_CHOICE" in
      [nN][oO]|[nN])
        log_info "正在追加暂存全部变动 (git add -A)..."
        git add -A
        ;;
      *)
        log_info "将仅提交当前已暂存的改动。"
        ;;
    esac
  fi
fi

# 二次确认暂存区是否有内容
if git diff --cached --quiet; then
  log_error "暂存区无任何可提交的内容，请先使用 'git add' 暂存改动或传入 '-a' 参数。"
  exit 1
fi

# ==============================================================================
# 4. 收集与校验提交信息 (Type, Scope, Breaking, Subject)
# ==============================================================================
VALID_TYPES="^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)$"

if [ "$IS_NON_INTERACTIVE" = true ]; then
  # 非交互式模式：校验传入参数
  TYPE="$CLI_TYPE"
  if ! echo "$TYPE" | grep -Eq "$VALID_TYPES"; then
    log_error "无效的提交类型: [$TYPE]。必须为下列之一:"
    log_error "feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
    exit 1
  fi

  SUBJECT=$(echo "$CLI_MSG" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  if [ -z "$SUBJECT" ]; then
    log_error "提交描述 (-m, --message) 不能为空！"
    exit 1
  fi

  SCOPE=$(echo "$CLI_SCOPE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  if [ "$CLI_BREAKING" = true ]; then
    BREAKING_FLAG="!"
  else
    BREAKING_FLAG=""
  fi
else
  # 交互式向导模式
  printf "\n%b请选择本次提交类型 (Commit Type):%b\n" "${COLOR_BOLD}" "${COLOR_RESET}"
  printf "  %b1)%b  feat     : 🚀 新特性 / 新功能 (Features)\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b2)%b  fix      : 🐛 缺陷与 Bug 修复 (Bug Fixes)\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b3)%b  docs     : 📝 仅文档变动 (Documentation)\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b4)%b  style    : 🎨 代码格式与排版调整（不影响逻辑，Style）\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b5)%b  refactor : 🚜 代码重构（既非新特性也非缺陷修复，Refactor）\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b6)%b  perf     : ⚡ 性能优化 (Performance)\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b7)%b  test     : 🧪 测试相关（新增用例或重构测试，Tests）\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b8)%b  build    : 📦 构建系统、外部依赖或脚手架调整 (Build)\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b9)%b  ci       : 👷 CI/CD 流水线与 GitHub Actions 修改 (CI)\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b10)%b chore    : 🧹 杂项维护（不改动源码与测试，Chore）\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b11)%b revert   : ⏪ 代码回滚 (Revert)\n" "${COLOR_GREEN}" "${COLOR_RESET}"
  printf "  %b0)%b  q / exit : 🚪 取消并退出\n\n" "${COLOR_YELLOW}" "${COLOR_RESET}"

  TYPE=""
  while [ -z "$TYPE" ]; do
    printf "%b请输入选项编号 [0-11]: %b" "${COLOR_BOLD}" "${COLOR_RESET}"
    read -r TYPE_CHOICE
    TYPE_CHOICE=$(echo "$TYPE_CHOICE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$TYPE_CHOICE" in
      1) TYPE="feat" ;;
      2) TYPE="fix" ;;
      3) TYPE="docs" ;;
      4) TYPE="style" ;;
      5) TYPE="refactor" ;;
      6) TYPE="perf" ;;
      7) TYPE="test" ;;
      8) TYPE="build" ;;
      9) TYPE="ci" ;;
      10) TYPE="chore" ;;
      11) TYPE="revert" ;;
      0|[qQ]|[eE][xX][iI][tT])
        log_warn "用户取消操作，退出提交向导。"
        exit 0
        ;;
      *)
        log_warn "无效选项，请输入 0 到 11 之间的编号。"
        ;;
    esac
  done

  # 收集可选影响范围
  printf "\n%b请输入影响范围 Scope (可选，如 core / cli / tools，留空按回车): %b" "${COLOR_BOLD}" "${COLOR_RESET}"
  read -r SCOPE
  SCOPE=$(echo "$SCOPE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

  # 收集破坏性更新标记
  printf "%b是否包含破坏性更新 (Breaking Changes)? [y/N]: %b" "${COLOR_BOLD}" "${COLOR_RESET}"
  read -r IS_BREAKING
  IS_BREAKING=$(echo "$IS_BREAKING" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  case "$IS_BREAKING" in
    [yY][eE][sS]|[yY])
      BREAKING_FLAG="!"
      ;;
    *)
      BREAKING_FLAG=""
      ;;
  esac

  # 收集提交描述
  SUBJECT=""
  while [ -z "$SUBJECT" ]; do
    printf "%b请输入提交描述 Subject (必填，简要概括本次变动): %b" "${COLOR_BOLD}" "${COLOR_RESET}"
    read -r SUBJECT
    SUBJECT=$(echo "$SUBJECT" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ -z "$SUBJECT" ]; then
      log_warn "提交描述不能为空，请重新输入。"
    fi
  done
fi

# 拼装提交消息 Header
if [ -n "$SCOPE" ]; then
  COMMIT_HEADER="${TYPE}(${SCOPE})${BREAKING_FLAG}: ${SUBJECT}"
else
  COMMIT_HEADER="${TYPE}${BREAKING_FLAG}: ${SUBJECT}"
fi

# ==============================================================================
# 5. 预览与确认
# ==============================================================================
printf "\n%b\n" "${COLOR_BOLD}${COLOR_CYAN}------------------- 拟生成的提交信息预览 -------------------${COLOR_RESET}"
printf "%b\n" "${COLOR_BOLD}${COLOR_GREEN}${COMMIT_HEADER}${COLOR_RESET}"
printf "%b\n\n" "${COLOR_BOLD}${COLOR_CYAN}------------------------------------------------------------${COLOR_RESET}"

if [ "$AUTO_CONFIRM" = true ] || [ ! -t 0 ]; then
  log_info "已指定 -y 或处于非交互环境，跳过人工确认，直接执行提交。"
else
  printf "%b是否确认以此信息执行提交? [Y/n]: %b" "${COLOR_BOLD}" "${COLOR_RESET}"
  read -r CONFIRM_COMMIT
  CONFIRM_COMMIT=$(echo "$CONFIRM_COMMIT" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  case "$CONFIRM_COMMIT" in
    [nN][oO]|[nN])
      log_warn "操作已由用户取消，未执行任何提交。"
      exit 0
      ;;
    *)
      ;;
  esac
fi

# ==============================================================================
# 6. 执行 Git Commit
# ==============================================================================
git commit -m "$COMMIT_HEADER"
log_success "代码提交成功！"

# ==============================================================================
# 7. 远程推送
# ==============================================================================
if [ "$CLI_PUSH" = true ]; then
  log_info "正在自动推送到 origin/${CURRENT_BRANCH}..."
  git push origin "$CURRENT_BRANCH"
  log_success "推送成功！"
elif [ -t 0 ] && [ "$AUTO_CONFIRM" = false ]; then
  printf "\n%b是否立即推送到远程分支 (origin/%s)? [y/N]: %b" "${COLOR_BOLD}" "$CURRENT_BRANCH" "${COLOR_RESET}"
  read -r CONFIRM_PUSH
  CONFIRM_PUSH=$(echo "$CONFIRM_PUSH" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  case "$CONFIRM_PUSH" in
    [yY][eE][sS]|[yY])
      log_info "正在推送到 origin/${CURRENT_BRANCH}..."
      git push origin "$CURRENT_BRANCH"
      log_success "推送成功！"
      ;;
    *)
      log_info "已跳过远程推送。你可以在就绪后随时运行 'git push origin ${CURRENT_BRANCH}'。"
      ;;
  esac
fi
