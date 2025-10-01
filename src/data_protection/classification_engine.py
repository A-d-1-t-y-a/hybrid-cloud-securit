"""
Automated Data Classification Engine for Hybrid Cloud Security Framework
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import spacy
from transformers import pipeline

from src.core.logging import get_logger

logger = get_logger(__name__)


class DataClassificationEngine:
    """Automated data classification engine using ML and NLP"""
    
    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")
        self.classifier = pipeline(
            "text-classification",
            model="microsoft/DialoGPT-medium",
            return_all_scores=True
        )
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.ml_classifier = MultinomialNB()
        self.classification_rules = self._load_classification_rules()
        self.trained = False
    
    def _load_classification_rules(self) -> Dict[str, List[str]]:
        """Load classification rules for different data types"""
        return {
            "PII": [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{3}\.\d{2}\.\d{4}\b',  # SSN with dots
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{3}-\d{3}-\d{4}\b',  # Phone
                r'\b\d{1,5}\s\w+\s(street|st|avenue|ave|road|rd|drive|dr|lane|ln|way|blvd)\b'  # Address
            ],
            "Financial": [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
                r'\b\d{9}\b',  # Bank routing
                r'\$\d{1,3}(,\d{3})*(\.\d{2})?\b',  # Currency
                r'\b(account|balance|transaction|payment|invoice)\b'
            ],
            "Medical": [
                r'\b\d{2}/\d{2}/\d{4}\b',  # Date
                r'\b(patient|diagnosis|treatment|medication|prescription)\b',
                r'\b\d{3}-\d{2}-\d{4}\b',  # Medical ID
                r'\b(blood|pressure|temperature|heart|rate)\b'
            ],
            "Confidential": [
                r'\b(confidential|secret|classified|proprietary|internal)\b',
                r'\b(contract|agreement|legal|terms|conditions)\b',
                r'\b(password|secret|key|token|credential)\b'
            ]
        }
    
    def classify_data(self, content: str, metadata: Optional[Dict] = None) -> Dict[str, any]:
        """Classify data content and return classification results"""
        try:
            # Rule-based classification
            rule_based_result = self._rule_based_classification(content)
            
            # ML-based classification
            ml_result = self._ml_based_classification(content)
            
            # NLP-based classification
            nlp_result = self._nlp_based_classification(content)
            
            # Combine results
            final_classification = self._combine_classifications(
                rule_based_result, ml_result, nlp_result
            )
            
            # Add metadata
            final_classification.update({
                "timestamp": datetime.utcnow().isoformat(),
                "content_hash": hashlib.sha256(content.encode()).hexdigest(),
                "metadata": metadata or {}
            })
            
            logger.info(f"Data classified: {final_classification['sensitivity_level']}")
            return final_classification
            
        except Exception as e:
            logger.error(f"Error in data classification: {str(e)}")
            return {
                "sensitivity_level": "Unknown",
                "confidence": 0.0,
                "classification_method": "error",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }
    
    def _rule_based_classification(self, content: str) -> Dict[str, any]:
        """Rule-based classification using regex patterns"""
        classifications = []
        confidence_scores = []
        
        for category, patterns in self.classification_rules.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    matches += 1
            
            if matches > 0:
                confidence = min(matches / len(patterns), 1.0)
                classifications.append(category)
                confidence_scores.append(confidence)
        
        if not classifications:
            return {
                "sensitivity_level": "Public",
                "confidence": 0.8,
                "classification_method": "rule_based"
            }
        
        # Determine highest confidence classification
        max_confidence_idx = confidence_scores.index(max(confidence_scores))
        primary_classification = classifications[max_confidence_idx]
        
        return {
            "sensitivity_level": primary_classification,
            "confidence": confidence_scores[max_confidence_idx],
            "classification_method": "rule_based",
            "matched_categories": classifications
        }
    
    def _ml_based_classification(self, content: str) -> Dict[str, any]:
        """ML-based classification using trained model"""
        if not self.trained:
            return {
                "sensitivity_level": "Unknown",
                "confidence": 0.0,
                "classification_method": "ml_based"
            }
        
        try:
            # Vectorize content
            content_vector = self.vectorizer.transform([content])
            
            # Predict classification
            prediction = self.ml_classifier.predict(content_vector)[0]
            confidence = self.ml_classifier.predict_proba(content_vector).max()
            
            return {
                "sensitivity_level": prediction,
                "confidence": confidence,
                "classification_method": "ml_based"
            }
        except Exception as e:
            logger.error(f"ML classification error: {str(e)}")
            return {
                "sensitivity_level": "Unknown",
                "confidence": 0.0,
                "classification_method": "ml_based"
            }
    
    def _nlp_based_classification(self, content: str) -> Dict[str, any]:
        """NLP-based classification using spaCy and transformers"""
        try:
            # Process with spaCy
            doc = self.nlp(content)
            
            # Extract entities
            entities = [ent.text for ent in doc.ents]
            entity_types = [ent.label_ for ent in doc.ents]
            
            # Check for sensitive entities
            sensitive_entities = []
            for entity, entity_type in zip(entities, entity_types):
                if entity_type in ['PERSON', 'ORG', 'GPE']:
                    sensitive_entities.append(entity)
            
            # Determine sensitivity based on entities
            if len(sensitive_entities) > 3:
                sensitivity_level = "Highly Sensitive"
                confidence = 0.9
            elif len(sensitive_entities) > 1:
                sensitivity_level = "Sensitive"
                confidence = 0.7
            else:
                sensitivity_level = "Public"
                confidence = 0.6
            
            return {
                "sensitivity_level": sensitivity_level,
                "confidence": confidence,
                "classification_method": "nlp_based",
                "entities": sensitive_entities
            }
            
        except Exception as e:
            logger.error(f"NLP classification error: {str(e)}")
            return {
                "sensitivity_level": "Unknown",
                "confidence": 0.0,
                "classification_method": "nlp_based"
            }
    
    def _combine_classifications(self, rule_result: Dict, ml_result: Dict, nlp_result: Dict) -> Dict[str, any]:
        """Combine different classification results"""
        # Weight different methods
        weights = {
            "rule_based": 0.4,
            "ml_based": 0.3,
            "nlp_based": 0.3
        }
        
        # Calculate weighted confidence
        total_confidence = (
            rule_result["confidence"] * weights["rule_based"] +
            ml_result["confidence"] * weights["ml_based"] +
            nlp_result["confidence"] * weights["nlp_based"]
        )
        
        # Determine final classification
        classifications = [rule_result, ml_result, nlp_result]
        valid_classifications = [c for c in classifications if c["sensitivity_level"] != "Unknown"]
        
        if not valid_classifications:
            final_sensitivity = "Unknown"
        else:
            # Use the classification with highest confidence
            best_classification = max(valid_classifications, key=lambda x: x["confidence"])
            final_sensitivity = best_classification["sensitivity_level"]
        
        return {
            "sensitivity_level": final_sensitivity,
            "confidence": total_confidence,
            "classification_method": "combined",
            "rule_based": rule_result,
            "ml_based": ml_result,
            "nlp_based": nlp_result
        }
    
    def train_classifier(self, training_data: List[Tuple[str, str]]) -> bool:
        """Train the ML classifier with labeled data"""
        try:
            if not training_data:
                return False
            
            # Prepare training data
            texts, labels = zip(*training_data)
            
            # Vectorize texts
            X = self.vectorizer.fit_transform(texts)
            
            # Train classifier
            self.ml_classifier.fit(X, labels)
            self.trained = True
            
            logger.info(f"Classifier trained with {len(training_data)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Training error: {str(e)}")
            return False
    
    def get_classification_rules(self) -> Dict[str, List[str]]:
        """Get current classification rules"""
        return self.classification_rules
    
    def add_classification_rule(self, category: str, pattern: str) -> bool:
        """Add new classification rule"""
        try:
            if category not in self.classification_rules:
                self.classification_rules[category] = []
            
            self.classification_rules[category].append(pattern)
            logger.info(f"Added rule for category {category}: {pattern}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding rule: {str(e)}")
            return False

