# Group_13_Cyber_Forensics_Research_paper
AI Driven Approaches to Cloud Log Forensics
Here is a complete, ready-to-use README section for your project with your **actual results filled in** based on your CSVs:

# AWS CloudTrail Malicious Activity Detection
This project focuses on leveraging both rule-based heuristics and machine learning algorithms to detect and categorize security threats within AWS CloudTrail logs. The key objectives are to reliably identify both general and specific types of malicious activity, aiding cloud forensics and incident response.


## 📁 Key Result Files

- **binary_classification_results.csv:**  
  Shows classifier performance (Accuracy, Precision, Recall, and F1-Score) for distinguishing between malicious and legitimate events.
- **multiclass_classification_results.csv:**  
  Summarizes classifier performance in predicting the specific type of attack (multi-class settings), using the same metrics.
- Both files are found in the repository’s `/results/` folder.



 📊 Results Overview

 **Binary Classification (Malicious vs. Legit)**

| Algorithm           | Accuracy | Precision | Recall | F1-Score |
|---------------------|----------|-----------|--------|----------|
| Random Forest       | 1.0000   | 1.0000    | 1.0000 | 1.0000   |
| Logistic Regression | 1.0000   | 1.0000    | 1.0000 | 1.0000   |
| Gradient Boosting   | 1.0000   | 1.0000    | 1.0000 | 1.0000   |

 **Multi-Class Classification (Attack Type)**

| Algorithm         | Accuracy | Precision | Recall | F1-Score |
|-------------------|----------|-----------|--------|----------|
| Decision Tree     | 1.0000   | 1.0000    | 1.0000 | 1.0000   |
| Random Forest     | 1.0000   | 1.0000    | 1.0000 | 1.0000   |
| Gradient Boosting | 1.0000   | 1.0000    | 1.0000 | 1.0000   |


 📄 **How to Use Results**

- The CSV files in `/results/` provide tabular performance metrics for each modeling task.
- You can cite these tables in your report, slides, or for further analysis to compare model performance.

**Conclusion**
The machine learning models achieved perfect scores on both binary and multi-class classification tasks for this dataset, showing exceptional ability to distinguish not only between benign and malicious events, but also to recognize the specific type of malicious behavior. These findings indicate a highly effective detection pipeline, which can greatly enhance cloud forensics and automated threat response.



