import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler,MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score, accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split, KFold, cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
import numpy as np
import warnings

df = pd.read_csv('dataset_malwares.csv')
warnings.filterwarnings("ignore")

for col in df.columns[1:]:
    data = df[col]
    unique_counts = df[col].value_counts()
    #unique_counts.plot(kind='bar', edgecolor='black')
    # plt.xlabel('Unique Values')
    # plt.ylabel('Count')
    # plt.title(f'Occurance of {col}')
    # plt.xticks(rotation=45)
    #plt.show()

high_var_columns = [
    'e_lfanew', 'NumberOfSections', 'TimeDateStamp', 'SizeOfOptionalHeader',
    'Characteristics', 'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
    'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
    'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
    'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
    'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfHeaders', 'SizeOfImage',
    'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'Malware',
    'SuspiciousImportFunctions', 'SectionsLength', 'SectionMinEntropy', 'SectionMinRawsize',
    'SectionMinVirtualsize', 'SectionMaxPhysical', 'SectionMaxVirtual', 'SectionMaxPointerData',
    'SectionMaxChar', 'DirectoryEntryImport', 'DirectoryEntryImportSize', 'DirectoryEntryExport',
    'ImageDirectoryEntryImport', 'ImageDirectoryEntryResource', 'ImageDirectoryEntrySecurity'
]

#crosscorelation to see if there's any dependencies.
df_reduced = df.drop(columns=['Name', 'Machine'])
df_reduced = df_reduced[high_var_columns]
correlation_matrix = df_reduced.corr()
# Visualize the correlation matrix using a heatmap
# plt.figure(figsize=(12, 10))
# sns.heatmap(correlation_matrix, annot=True, fmt=".2f", cmap='coolwarm')
# plt.title('Correlation Matrix')
#plt.show()

strong_correlations = correlation_matrix[correlation_matrix.abs() > 0.5]
strong_correlations = strong_correlations[strong_correlations.abs() < 0.95]
strong_pairs = strong_correlations.unstack().dropna().sort_values(ascending=False)
strong_pairs = strong_pairs[strong_pairs < 1]
print("Strongly correlated feature pairs:")
print(strong_pairs)

strong_pairs_columns = set()
for pair in strong_pairs.index:
    strong_pairs_columns.add(pair[0])
    strong_pairs_columns.add(pair[1])
df_reduced_strong = df[list(strong_pairs_columns)]

print(list(strong_pairs_columns))

# Standardize the data
scaler = MinMaxScaler()
df_scaled = scaler.fit_transform(df_reduced_strong)

#PCA for dimensionality reduction
pca = PCA(n_components=2)
df_pca = pca.fit_transform(df_scaled)
df_reduced_strong['PCA1'] = df_pca[:, 0]
df_reduced_strong['PCA2'] = df_pca[:, 1]

# Plot PCA results with centroids
plt.figure(figsize=(12, 10))
sns.scatterplot(x='PCA1', y='PCA2', hue='Malware', data=df_reduced_strong, palette='viridis')
plt.title('K-Means Clustering with PCA')
plt.xlabel('PCA1')
plt.ylabel('PCA2')
plt.legend()
plt.show()

perplexities = [5]
learning_rates = [10]
best_score = -1
best_params = None

#Try different t-SNE configurations
for perplexity in perplexities:
    for lr in learning_rates:
        tsne = TSNE(n_components=2, perplexity=perplexity, learning_rate=lr, random_state=42, init="pca", n_iter=1000)
        tsne_results = tsne.fit_transform(df_scaled)

        # Compute Silhouette Score
        silhouette_avg = silhouette_score(df_scaled, tsne_results[:, 0])  
        
        print(f"Perplexity: {perplexity}, Learning Rate: {lr}, Silhouette Score: {silhouette_avg:.4f}")

        if silhouette_avg > best_score:
            df_tsne = tsne.fit_transform(df_scaled)
            df_reduced_strong['TSNE1'] = df_tsne[:, 0]
            df_reduced_strong['TSNE2'] = df_tsne[:, 1]

            best_score = silhouette_avg
            best_params = (perplexity, lr)

print(f"\nBest Configuration -> Perplexity: {best_params[0]}, Learning Rate: {best_params[1]}, Silhouette Score: {best_score:.4f}")

# Plot t-SNE results with centroids
plt.figure(figsize=(12, 10))
sns.scatterplot(x='TSNE1', y='TSNE2', hue='Malware', data=df_reduced_strong, palette='viridis')
plt.title('K-Means Clustering with t-SNE')
plt.xlabel('TSNE1')
plt.ylabel('TSNE2')
plt.legend()
plt.show()

# Define number of neighbors
neighbors = 5

# Initialize K-Fold cross-validation with 10 folds
kf = KFold(n_splits=10, shuffle=True, random_state=42)

# Feature sets and target variable
X_sets = [
    df_reduced_strong.drop(columns=['Malware', 'PCA1', 'PCA2', 'TSNE1', 'TSNE2']),  # No reduction
    df_reduced_strong[['PCA1', 'PCA2']],  # PCA
    df_reduced_strong[['TSNE1', 'TSNE2']]  # t-SNE
]
Y = df_reduced_strong['Malware']

# Scaling control: 1 = Apply scaler, 0 = No scaling
scale = [1, 0, 0]

print("----------------------------------------------------------------------------------------------")
print("k-Nearest Neighbours")
print("----------------------------------------------------------------------------------------------")

# Iterate through each feature set (No Reduction, PCA, t-SNE)
for feature_set_idx, X in enumerate(X_sets):
    print(f"Feature Set {feature_set_idx + 1}: {'No Reduction' if feature_set_idx == 0 else 'PCA' if feature_set_idx == 1 else 't-SNE'}")
    
    accuracies = []
    confusion_matrices_KNN = []

    for i, (train_index, test_index) in enumerate(kf.split(X), start=1):
        X_train, X_test = X.iloc[train_index], X.iloc[test_index]
        y_train, y_test = Y.iloc[train_index], Y.iloc[test_index]

        # Apply scaling only if scale[feature_set_idx] == 1
        if scale[feature_set_idx] == 1:
            X_train = scaler.fit_transform(X_train)
            X_test = scaler.transform(X_test)  # Use transform instead of fit_transform

        # Train KNN classifier
        knn = KNeighborsClassifier(n_neighbors=neighbors)
        knn.fit(X_train, y_train)

        # Make predictions and compute accuracy
        y_pred = knn.predict(X_test)
        accuracies.append(accuracy_score(y_test, y_pred))

        # Store confusion matrix
        confusion_matrices_KNN.append(pd.DataFrame(
            confusion_matrix(y_test, y_pred),
            index=['Actual Yes', 'Actual No'],
            columns=['Predicted Yes', 'Predicted No']
        ))

        print(f'Accuracy for KNN fold {i}: {accuracies[-1]}')

    print("----------------------------------------------------------------------------------------------")
    for i, cm in enumerate(confusion_matrices_KNN, start=1):
        print(f'Confusion Matrix for KNN Fold {i}:')
        print(cm)

    print("----------------------------------------------------------------------------------------------")
    mean_accuracy = np.mean(accuracies)
    print(f'Mean Accuracy for KNN n={neighbors}: {mean_accuracy}')
    print("----------------------------------------------------------------------------------------------")
