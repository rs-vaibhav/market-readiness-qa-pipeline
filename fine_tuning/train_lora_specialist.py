"""
LoRA / QLoRA Parameter-Efficient Fine-Tuning Pipeline.
Fine-tunes open-source base models (Llama 3.2, Qwen 2.5 Coder) on specialized
QA review, defect root-cause analysis, and OWASP security auditing datasets.

Supports:
- 4-bit / 8-bit Quantized Low-Rank Adaptation (QLoRA)
- Hugging Face PEFT + TRL SFTTrainer
- Export to GGUF format for local deployment in Ollama
"""

import argparse
import os
import sys
from pathlib import Path


def run_training_pipeline(
    base_model: str = "meta-llama/Llama-3.2-3B-Instruct",
    dataset_path: str = "fine_tuning/data/qa_tuning_chatml.jsonl",
    output_dir: str = "models/qa-specialist-adapter",
    epochs: int = 3,
    batch_size: int = 2,
    gradient_accumulation_steps: int = 4,
    learning_rate: float = 2e-4,
    max_seq_length: int = 2048,
) -> None:
    """
    Executes LoRA adaptation on base model using the curated QA dataset.
    Requires: pip install transformers peft trl bitsandbytes datasets
    """
    print(f"Initializing LoRA Fine-Tuning Pipeline...")
    print(f"Base Model: {base_model}")
    print(f"Dataset Path: {dataset_path}")
    print(f"Output Adapter Directory: {output_dir}")

    try:
        import torch
        from datasets import load_dataset
        from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments
        from trl import SFTTrainer
    except ImportError as e:
        print(f"[CONFIGURATION NOTE] Missing fine-tuning packages: {e}")
        print("To execute local LoRA weight adaptation, install training dependencies:")
        print("  pip install torch transformers peft trl bitsandbytes datasets accelerate")
        print("\nAlternatively, deploy the pre-configured Ollama specialized model directly:")
        print("  ollama create qa-auditor-specialist -f fine_tuning/Modelfile.qa-auditor")
        return

    # Check GPU availability
    device_map = "auto" if torch.cuda.is_available() or torch.backends.mps.is_available() else None

    # 4-bit Quantization Configuration
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    ) if torch.cuda.is_available() else None

    # Load Tokenizer & Model
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        quantization_config=bnb_config,
        device_map=device_map,
        trust_remote_code=True,
    )

    if torch.cuda.is_available():
        model = prepare_model_for_kbit_training(model)

    # LoRA Target Modules Configuration
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # Load Dataset
    dataset = load_dataset("json", data_files=dataset_path, split="train")

    # Training Arguments
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        learning_rate=learning_rate,
        weight_decay=0.01,
        warmup_ratio=0.05,
        logging_steps=10,
        save_strategy="epoch",
        fp16=torch.cuda.is_available(),
        optim="paged_adamw_8bit" if torch.cuda.is_available() else "adamw_torch",
        report_to="none",
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        peft_config=lora_config,
        dataset_text_field="messages",
        max_seq_length=max_seq_length,
        tokenizer=tokenizer,
        args=training_args,
    )

    print("Beginning LoRA fine-tuning training run...")
    trainer.train()

    print(f"Saving adapted LoRA weights to: {output_dir}")
    trainer.model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    print("\nFine-tuning completed successfully.")
    print("To convert and import into Ollama:")
    print(f"  1. Merge adapter: python -m peft.merge --base {base_model} --adapter {output_dir} --out merged_model")
    print("  2. Convert to GGUF: python llama.cpp/convert_hf_to_gguf.py merged_model --outfile qa-specialist.gguf")
    print("  3. Register in Ollama: ollama create qa-auditor-specialist -f fine_tuning/Modelfile.qa-auditor")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LoRA Fine-Tuning Pipeline for QA & AppSec Audit Specialist")
    parser.add_argument("--base_model", type=str, default="meta-llama/Llama-3.2-3B-Instruct")
    parser.add_argument("--dataset", type=str, default="fine_tuning/data/qa_tuning_chatml.jsonl")
    parser.add_argument("--output_dir", type=str, default="models/qa-specialist-adapter")
    parser.add_argument("--epochs", type=int, default=3)
    args = parser.parse_args()

    run_training_pipeline(
        base_model=args.base_model,
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        epochs=args.epochs,
    )
