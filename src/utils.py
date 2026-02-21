from typing import List, Optional, Any, Dict, Union
from pathlib import Path
from PIL import Image

from src.ocr_extractor import ImageToText
from src.scam_analyzer import calculate_scam_score
from src.scam_grouper import ScamGrouper

"""Utility functions for scam detection and analysis."""


def analyze_image_for_scams(
    image_input: Union[str, Path, Image.Image],
    ocr_languages: Optional[List[str]] = None,
    use_gpu: bool = False
) -> Dict[str, Any]:
    """
    Complete pipeline to analyze an image for scams.
    
    Takes an image, extracts text via OCR, analyzes it for scam indicators,
    and categorizes the type of scam detected.
    
    Args:
        image_input: Path to image file, PIL Image object, or image path string
        ocr_languages: Languages for OCR recognition. Defaults to ['en']
        use_gpu: Whether to use GPU acceleration for OCR. Defaults to False
        
    Returns:
        Dictionary with:
            - success: bool indicating if analysis completed
            - extracted_text: str of text extracted from image
            - scam_score: int (0-100) indicating likelihood of scam
            - scam_types: set of detected scam types
            - flags: list of specific indicators found
            - confidence: float OCR confidence score (0-1)
            - error: str error message if analysis failed
    """
    try:
        # Step 1: Initialize OCR and extract text from image
        ocr = ImageToText(languages=ocr_languages, gpu=use_gpu)
        ocr_result = ocr.extract_text(image_input)
        
        if not ocr_result["success"]:
            return {
                "success": False,
                "extracted_text": "",
                "scam_score": 0,
                "scam_types": set(),
                "flags": [],
                "confidence": 0.0,
                "error": ocr_result.get("error", "OCR extraction failed")
            }
        
        extracted_text = ocr_result["text"]
        
        # Validate extracted text quality
        if not ocr.validate_text_quality(extracted_text):
            return {
                "success": False,
                "extracted_text": extracted_text,
                "scam_score": 0,
                "scam_types": set(),
                "flags": [],
                "confidence": ocr_result["avg_confidence"],
                "error": "Extracted text did not meet quality standards"
            }
        
        # Step 2: Analyze extracted text for scam indicators
        analysis_result = calculate_scam_score(extracted_text)
        scam_score = analysis_result["score"]
        flags = analysis_result["flags"]
        
        # Step 3: Categorize scam type based on detected flags
        grouper = ScamGrouper()
        scam_types = grouper.detect_scam_type(flags)
        
        return {
            "success": True,
            "extracted_text": extracted_text,
            "scam_score": scam_score,
            "scam_types": scam_types,
            "flags": flags,
            "confidence": ocr_result["avg_confidence"],
            "error": None
        }
        
    except Exception as e:
        return {
            "success": False,
            "extracted_text": "",
            "scam_score": 0,
            "scam_types": set(),
            "flags": [],
            "confidence": 0.0,
            "error": f"Pipeline error: {str(e)}"
        }
