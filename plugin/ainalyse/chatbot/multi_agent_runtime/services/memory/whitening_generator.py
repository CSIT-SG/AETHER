"""
Whitening Parameter Generator for Vector RAG.

PURPOSE: This script is provided for the reproducibility of the 'whitening_mu.npy' 
and 'whitening_W.npy' files. It allows developers to regenerate these parameters 
from scratch to ensure consistency or to adapt the vector engine to different models.

EXTERNAL RESOURCES:
1. Embedding Model: 'qwen3-embedding-0.6b-q4_k_m.gguf'
   - Found at: https://huggingface.co/enacimie/Qwen3-Embedding-0.6B-Q4_K_M-GGUF
2. Training Datasets: WikiText-103 and CodeSearchNet (Parquet format)
   - These are standard open-source datasets available on Hugging Face Datasets.
   - You must download these locally and update the paths in this script accordingly.
"""

import pandas as pd
import glob
import numpy as np
import os
import torch
from tqdm import tqdm
from llama_cpp import Llama
import re
from scipy.stats import norm

# --- Configuration & Paths ---

# Update these paths to point to your local dataset downloads
WIKITEXT_PATH = "C:/Users/bob/Downloads/turboquantr/wikitext/wikitext-103-raw-v1/*.parquet"
CODESEARCHNET_PATH = "C:/Users/bob/Downloads/turboquantr/codesearchnet/pair/*.parquet"
OUTPUT_DIR = "C:/Users/bob/Downloads/turboquantr/"

gpu_layers = -1 if torch.cuda.is_available() else 0
LLAMA_PATH = os.path.join(os.path.dirname(__file__), "qwen3-embedding-0.6b-q4_k_m.gguf")

# Initialize the local embedding model
LLAMA = Llama(
    model_path=LLAMA_PATH, 
    embedding=True, 
    use_mmap=False, 
    n_ctx=512, 
    n_batch=512, 
    n_ubatch=512, 
    n_gpu_layers=gpu_layers, 
    pooling_type=1, 
    flash_attn=True,
    logits_all=True, 
    verbose=False
)


import numpy as np
from tqdm import tqdm

pattern = re.compile(r'[^a-zA-Z0-9\s]')

def clean_text(text):
    # 1. Remove special characters
    text = pattern.sub('', text)
    # 2. (Optional) Collapse multiple spaces into one
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_embeddings_in_batches(text_list, batch_size=8):
    all_embeddings = []
    for i in range(0, len(text_list), batch_size):
        batch = text_list[i : i + batch_size]
        batch = [str(t).encode("utf-8", "ignore").decode("utf-8") for t in batch]
        
        try:
            res = LLAMA.create_embedding(batch)
            vectors = [item['embedding'] for item in res['data']]
            all_embeddings.append(np.array(vectors))
            print(len(all_embeddings))
        except Exception as e:
            print(f"Error at index {i}: {e}")
            # If it fails, print the batch to see which string caused it
            print(len(batch))
            print(([len(LLAMA.tokenize(s.encode('utf-8'))) for s in batch]))
            break
    return np.vstack(all_embeddings)

def compute_whitening_params(embeddings, ridge=1e-5):
    """
    Computes whitening parameters while strictly maintaining 
    the original dimensionality (no truncation).
    """
    # 1. Calculate Mean and Center
    mu = np.mean(embeddings, axis=0)
    centered = embeddings - mu
    
    # 2. Covariance with Ridge Regularization
    # The Ridge ensures the matrix is "Full Rank" so SVD finds all 1024 dims
    dim = embeddings.shape[1]
    cov = np.cov(centered, rowvar=False) + ridge * np.eye(dim)
    
    # 3. Singular Value Decomposition
    u, s, vh = np.linalg.svd(cov)
    
    # 4. PCA Whitening Matrix (Full Rank)
    # We use ALL dimensions (no 'k' slicing) to keep shape at (1024, 1024)
    s_inv = 1.0 / np.sqrt(s) 
    W = u @ np.diag(s_inv) @ u.T
    
    # Note: If you need ZCA (Rotation-aligned), use:
    # W = u @ np.diag(s_inv) @ u.T
    
    return mu, W

def compute_pca_weights(data):
    mean = np.mean(data, axis=0)
    centered_data = data - mean

    u, s, vh = np.linalg.svd(centered_data, full_matrices=False)

    def get_pca_target_energy(s, n_samples, target_percent=0.99):
        explained_variance = (s**2) / (n_samples - 1)
        variance_ratio = explained_variance / np.sum(explained_variance)
        
        # Calculate cumulative sum of energy
        cumulative_variance = np.cumsum(variance_ratio)
        
        # Find the first index where we hit our target
        n_components = np.argmax(cumulative_variance >= target_percent) + 1
        return n_components
    
    n_components = get_pca_target_energy(s, data.shape[0])
    pca_matrix = vh[:n_components].T

    return mean, pca_matrix


def generate_universal_codebook():
    # This perfectly centers the 256 points within their respective intervals
    probs = np.linspace(0, 1, 256 + 1)[1:-1] # Gives 255 points, or...

    # Better: use the (i + 0.5) / N formula
    indices = np.arange(256)
    probs = (indices + 0.5) / 256
    codebook = norm.ppf(probs).astype(np.float32)
    
    return codebook

def create_turbo_codebook(bits=4):
    """Generates optimal Lloyd-Max centroids for a N(0,1) distribution."""
    num_bins = 2**bits
    # NF4 math: equal-area quantiles
    # We use num_bins + 1 boundaries to create num_bins centers
    offsets = np.linspace(0, 1, num_bins + 2)[1:-1]
    centroids = norm.ppf(offsets)
    
    # Ensure they are torch tensors for your search pipeline
    return torch.from_numpy(centroids).float()

all_text = []

files = glob.glob("C:/Users/bob/Downloads/turboquantr/wikitext/wikitext-103-raw-v1/*.parquet")
total_target = 10000
samples_per_file = total_target // len(files)

for f in files:
    # 1. Open metadata
    temp_df = pd.read_parquet(f, engine='pyarrow')
    cols = temp_df.columns.tolist()
    
    # 2. Identify column
    target_col = next((c for c in ['code', 'text', 'code_content'] if c in cols), None)
    
    if not target_col:
        print(f"Skipping {f}: No recognizable column found.")
        continue

    # 3. Read only the specific column
    df = pd.read_parquet(f, columns=[target_col])

    # --- THE CLEANING PIPELINE ---
    
    # A. Drop NaNs and cast to string
    series = df[target_col].dropna().astype(str)
    
    # B. Strip special characters (keeping alphanumeric and spaces)
    series = series.str.replace(r'[^a-zA-Z0-9\s]', '', regex=True)
    
    # C. Standardize whitespace (converts tabs/newlines to a single space)
    # This effectively removes "empty lines" inside a string
    series = series.str.replace(r'\s+', ' ', regex=True).str.strip()
    
    # D. Final Filter: Remove strings that are now empty or just whitespace
    clean_series = series[series != ""]
    
    if clean_series.empty:
        continue
    
    # 4. Take the sample from the CLEAN series, not the original df
    n_to_take = min(len(clean_series), samples_per_file)
    sample_data = clean_series.sample(n=n_to_take).tolist()
    
    all_text.extend(sample_data)
    
    # Explicitly clear memory
    del df
    del clean_series

files = glob.glob("C:/Users/bob/Downloads/turboquantr/codesearchnet/pair/*.parquet")
total_target = 10000
samples_per_file = total_target // len(files)

for f in files:
    # 1. Open metadata
    temp_df = pd.read_parquet(f, engine='pyarrow')
    cols = temp_df.columns.tolist()
    
    # 2. Identify column
    target_col = next((c for c in ['code', 'text', 'code_content'] if c in cols), None)
    
    if not target_col:
        print(f"Skipping {f}: No recognizable column found.")
        continue

    # 3. Read only the specific column
    df = pd.read_parquet(f, columns=[target_col])

    # --- THE CLEANING PIPELINE ---
    
    # A. Drop NaNs and cast to string
    series = df[target_col].dropna().astype(str)
    
    # B. Strip special characters (keeping alphanumeric and spaces)
    series = series.str.replace(r'[^a-zA-Z0-9\s]', '', regex=True)
    
    # C. Standardize whitespace (converts tabs/newlines to a single space)
    # This effectively removes "empty lines" inside a string
    series = series.str.replace(r'\s+', ' ', regex=True).str.strip()
    
    # D. Final Filter: Remove strings that are now empty or just whitespace
    clean_series = series[series != ""]
    
    if clean_series.empty:
        continue
    
    # 4. Take the sample from the CLEAN series, not the original df
    n_to_take = min(len(clean_series), samples_per_file)
    sample_data = clean_series.sample(n=n_to_take).tolist()
    
    all_text.extend(sample_data)
    
    # Explicitly clear memory
    del df
    del clean_series

# print(len(all_text))
# with open("C:\\Users\\bob\\Downloads\\turboquantr\\data.txt", "w", encoding="utf-8") as f:
#     for item in all_text:
#         f.write(item + "\n\n")

vectors = get_embeddings_in_batches(all_text)
# vectors = np.load('C:\\Users\\bob\\Downloads\\turboquantr\\vectors.npz')['vectors']
mu, W = compute_whitening_params(vectors)

# mean, pca_matrix = compute_pca_weights(raw_embeddings)
# reduced_data = np.dot(raw_embeddings - mean, pca_matrix)
# mu, W = compute_whitening_params(raw_embeddings)


np.savez_compressed('C:\\Users\\bob\\Downloads\\turboquantr\\vectors.npz', vectors=vectors)

# np.save('C:\\Users\\bob\\Downloads\\turboquantr\\pca_mean.npy', mean)
# np.save('C:\\Users\\bob\\Downloads\\turboquantr\\pca_matrix.npy', pca_matrix)
np.save('C:\\Users\\bob\\Downloads\\turboquantr\\whitening_mu.npy', mu)
np.save('C:\\Users\\bob\\Downloads\\turboquantr\\whitening_W.npy', W)

# codebook = create_turbo_codebook(bits=4)
# torch.save(codebook, 'C:\\Users\\bob\\Downloads\\turboquantr\\codebook.pt')
