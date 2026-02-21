import cv2
import easyocr
import numpy as np
from PIL import Image
from pathlib import Path
from typing import Optional, Dict, Any

class ImageToText:
    """Extract text from images using EasyOCR."""
    
    def __init__(self, languages: Optional[list] = None, gpu: bool = False):
        """
        Initialize OCR reader.
        
        Args:
            languages: Languages to recognize. Defaults to ['en']
            gpu: Whether to use GPU acceleration. Defaults to False
        """
        self.languages = languages or ['en']
        self.reader = easyocr.Reader(self.languages, gpu=gpu)
    
    def preprocess_image(self, image_input) -> np.ndarray:
        """
        Preprocess image for better OCR accuracy.
        
        Args:
            image_input: PIL Image or file path string
            
        Returns:
            Preprocessed image as numpy array
        """
        # Convert PIL Image to numpy array if needed
        if isinstance(image_input, Image.Image):
            image = np.array(image_input)
        else:
            image = cv2.imread(str(image_input))
            if image is None:
                raise ValueError(f"Failed to read image from {image_input}")
        
        # Ensure image is in BGR format
        if len(image.shape) == 2:  # Grayscale
            gray = image
        else:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Apply contrast enhancement
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        
        # Denoise
        denoised = cv2.fastNlMeansDenoising(enhanced, h=10)
        
        return denoised
    
    def extract_text(self, image_input) -> Dict[str, Any]:
        """
        Extract text from image using EasyOCR.
        
        Args:
            image_input: PIL Image or file path string
            
        Returns:
            Dictionary with extracted text and confidence scores
        """
        try:
            # Preprocess image
            preprocessed = self.preprocess_image(image_input)
            
            # Run OCR
            results = self.reader.readtext(preprocessed)
            
            # Extract text and confidence - unpack bbox, text, confidence from each result
            extracted_data = []
            confidence_scores = []
            for result in results:
                _, text, confidence = result
                extracted_data.append(text)
                confidence_scores.append(confidence)
            
            extracted_text = "\n".join(extracted_data)
            
            return {
                "success": True,
                "text": extracted_text,
                "raw_results": results,
                "avg_confidence": float(np.mean(confidence_scores)) if confidence_scores else 0.0,
                "confidence_scores": confidence_scores
            }
        except Exception as e:
            return {
                "success": False,
                "text": "",
                "raw_results": [],
                "avg_confidence": 0.0,
                "confidence_scores": [],
                "error": str(e)
            }
    
    def validate_text_quality(self, text: str, min_length: int = 5) -> bool:
        """
        Validate if extracted text meets quality standards.
        
        Args:
            text: Extracted text
            min_length: Minimum character length
            
        Returns:
            True if text passes validation
        """
        if not text or len(text.strip()) < min_length:
            return False
        return True