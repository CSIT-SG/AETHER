$REPO_ROOT = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SOURCE_PLUGIN_DIR = Join-Path $REPO_ROOT "plugin"
$EMBEDDING_MODEL = "https://huggingface.co/enacimie/Qwen3-Embedding-0.6B-Q4_K_M-GGUF/resolve/main/qwen3-embedding-0.6b-q4_k_m.gguf"
$TIKTOKEN = "https://huggingface.co/Qwen/Qwen-7B/resolve/e08ed081a0cc944afe2c2cbf26375d21fde97b93/qwen.tiktoken"

# Updated path to match the new multi_agent_runtime architecture
$embedding = Join-Path $SOURCE_PLUGIN_DIR "ainalyse/chatbot/multi_agent_runtime/services/memory/memory_resources"
$tiktoken_file = Join-Path $embedding "qwen.tiktoken"
$model_file = Join-Path $embedding "qwen3-embedding-0.6b-q4_k_m.gguf"

if (-not (Test-Path $embedding)) {
    New-Item -ItemType Directory -Path $embedding -Force
}

if (-not (Test-Path $tiktoken_file)) {
    Write-Host "Downloading qwen.tiktoken..." -ForegroundColor Cyan
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $TIKTOKEN -OutFile $tiktoken_file -ErrorAction Stop
        $ProgressPreference = 'Continue'
    } catch {
        Write-Host "Failed to download tiktoken file: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "qwen.tiktoken already exists." -ForegroundColor Green
}

if (-not (Test-Path $model_file)) {
    Write-Host "Downloading qwen3-embedding-0.6b-q4_k_m.gguf..." -ForegroundColor Cyan
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $EMBEDDING_MODEL -OutFile $model_file -ErrorAction Stop
        $ProgressPreference = 'Continue'
    } catch {
        Write-Host "Failed to download embedding model file: $($_.Exception.Message)" -ForegroundColor Red      
    }
} else {
    Write-Host "qwen3-embedding-0.6b-q4_k_m.gguf already exists." -ForegroundColor Green
}
