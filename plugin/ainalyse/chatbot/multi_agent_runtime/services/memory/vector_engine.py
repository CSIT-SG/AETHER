from __future__ import annotations

import base64
import gc
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Tuple

import numpy as np
import numpy.typing as npt
import tiktoken
from scipy.stats import norm

# Try to import llama_cpp, handle if not installed
try:
    from llama_cpp import Llama
    HAS_LLAMA = True
except ImportError:
    HAS_LLAMA = False

class TiktokenConstants(Enum):
    ENDOFTEXT = 151643
    IMSTART = 151644
    IMEND = 151645

def get_resource_dir() -> str:
    """Get the directory where memory resource files are stored."""
    # We'll place resources in a folder relative to this file
    return os.path.join(os.path.dirname(__file__), "memory_resources")

# Constants for Vector Math
EPSILON = 1e-9
GAMMA = 1.233
SEED = 6767
BITS = 4
DIM = 1024

class VectorEngine:
    """Engine for local embeddings and vector quantization using Qwen and TurboQuant."""
    
    _instance = None
    _llama = None
    _encoder = None
    _mu = None
    _w = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(VectorEngine, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.res_dir = get_resource_dir()
        self.llama_path = os.path.join(self.res_dir, "qwen3-embedding-0.6b-q4_k_m.gguf")
        self.tiktoken_path = os.path.join(self.res_dir, "qwen.tiktoken")
        self.mu_path = os.path.join(self.res_dir, "whitening_mu.npy")
        self.w_path = os.path.join(self.res_dir, "whitening_w.npy")
        self.quant_engine = TurboQuantEngine(dim=DIM, bits=BITS, seed=SEED)

    @property
    def llama(self):
        if self._llama is None and HAS_LLAMA:
            if os.path.exists(self.llama_path):
                self._llama = Llama(
                    model_path=self.llama_path,
                    embedding=True,
                    use_mmap=True,
                    n_ctx=512,
                    n_batch=128,
                    n_ubatch=128,
                    n_gpu_layers=0,
                    pooling_type=1,
                    flash_attn=True,
                    logits_all=False,
                    verbose=False,
                )
        return self._llama

    @property
    def encoder(self):
        if self._encoder is None:
            if os.path.exists(self.tiktoken_path):
                with open(self.tiktoken_path, "rb") as f:
                    contents = f.read()
                ranks = {base64.b64decode(token): int(rank) for token, rank in (line.split() for line in contents.splitlines() if line)}
                self._encoder = tiktoken.Encoding(
                    name="qwen3_coder",
                    pat_str=r"""(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+""",
                    mergeable_ranks=ranks,
                    special_tokens={
                        "<|endoftext|>": TiktokenConstants.ENDOFTEXT.value,
                        "<|im_start|>": TiktokenConstants.IMSTART.value,
                        "<|im_end|>": TiktokenConstants.IMEND.value,
                    },
                )
        return self._encoder

    @property
    def whitening_data(self) -> Tuple[npt.NDArray[np.float32] | None, npt.NDArray[np.float32] | None]:
        if self._mu is None and os.path.exists(self.mu_path):
            self._mu = np.load(self.mu_path).astype(np.float32)
        if self._w is None and os.path.exists(self.w_path):
            self._w = np.load(self.w_path).astype(np.float32)
        return self._mu, self._w

    def create_vector(self, string: str) -> npt.NDArray[np.float32] | None:
        """Generate a normalized embedding vector from a text string."""
        if not HAS_LLAMA or self.llama is None:
            return None
        
        mu, w = self.whitening_data
        if mu is None or w is None:
            return None

        embeddings = np.array(self.llama.create_embedding(string)["data"][0]["embedding"], dtype=np.float32)
        raw_vec = embeddings - mu
        whiten = raw_vec @ w
        norm_val = np.linalg.norm(whiten, ord=2, axis=-1, keepdims=True)
        return whiten / (norm_val + EPSILON)

    def encode_quantized(self, vector: npt.NDArray[np.float32]) -> Tuple[npt.NDArray[np.uint8], npt.NDArray[np.uint8], npt.NDArray[np.float16]]:
        """Encode a vector using TurboQuant quantization."""
        return self.quant_engine.encode(vector)

class TurboQuantEngine:
    """TurboQuant vector quantization engine for efficient semantic search."""

    def __init__(self, dim: int, bits: int = BITS, seed: int = SEED) -> None:
        self.dim = dim
        self.bits = bits
        self.gamma = GAMMA / dim
        offsets = np.linspace(0, 1, (2**bits) + 2)[1:-1]
        self.codebook = norm.ppf(offsets).astype(np.float32)
        np.random.seed(seed)
        h = np.random.randn(dim, dim)
        q, _r = np.linalg.qr(h)
        self.rotation_matrix = q.astype(np.float32)

    def encode(self, x: npt.NDArray[np.float32]) -> Tuple[npt.NDArray[np.uint8], npt.NDArray[np.uint8], npt.NDArray[np.float16]]:
        norm_val = np.linalg.norm(x, ord=2, axis=-1, keepdims=True)
        x_unit = x / (norm_val + EPSILON)
        x_rotated = x_unit @ self.rotation_matrix.T
        dist = np.abs(x_rotated[..., np.newaxis] - self.codebook)
        indices = np.argmin(dist, axis=-1).astype(np.uint8)
        quantized_vals = self.codebook[indices.astype(np.int64)]
        residual = x_rotated - quantized_vals
        signs = (residual >= 0).astype(np.uint8)
        powers = (2 ** np.arange(8)).astype(np.uint8)
        packed_signs = (signs.reshape(-1, 8) * powers).sum(axis=-1, dtype=np.uint8)
        return indices, packed_signs, norm_val.astype(np.float16)

    def compute_scores(self, query_vector: npt.NDArray[np.float32], codes: npt.NDArray[np.uint8], signs: npt.NDArray[np.uint8]) -> npt.NDArray[np.float32]:
        """Compute similarity scores between a query vector and quantized stored vectors."""
        if query_vector.ndim > 1:
            query_vector = query_vector.squeeze()
        
        query_norm = np.linalg.norm(query_vector, ord=2)
        query_unit = (query_vector / (query_norm + EPSILON)).astype(np.float32)
        query_rotated = query_unit @ self.rotation_matrix.T

        # Unpack signs
        unpacked = np.unpackbits(signs, axis=-1, bitorder="little")
        signs_float = unpacked.reshape(signs.shape[0], -1).astype(np.float32) * 2.0 - 1.0

        nudge = (signs_float @ query_rotated) * self.gamma
        codebook_vals = self.codebook[codes.astype(np.int64)]
        scores = (codebook_vals * query_rotated).sum(axis=-1)
        
        final_scores = (scores + nudge) / (np.linalg.norm(scores + nudge) + EPSILON)
        return final_scores.astype(np.float32)
