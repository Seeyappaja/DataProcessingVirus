import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler,MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score, accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split, KFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score, recall_score
import numpy as np
import warnings

settings = [0,0]
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
df_reduced = df.drop(columns=['Name', 'Machine','e_magic',
'SectionMaxEntropy',
'SectionMaxRawsize',
'SectionMaxVirtualsize',
'SectionMinPhysical',
'SectionMinVirtual',
'SectionMinPointerData',
'SectionMainChar'])
#df_reduced = df_reduced[high_var_columns]
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


df_reduced_strong['Malware'].value_counts().plot(kind='bar', edgecolor='black')
plt.xlabel('Unique Values')
plt.ylabel('Count')
plt.title(f'Occurance of Malware')
plt.xticks(rotation=45)
plt.show()

Y = df_reduced_strong["Malware"]
X = df_reduced_strong.drop(columns=["Malware"])

df_reduced_strong, df_validation, df_reduced_strong_y, df_validation_y = train_test_split(X,Y, test_size=0.1, shuffle=True)
df_reduced_strong["Malware"] = df_reduced_strong_y

# Standardize the data
if settings[0] == 1:
    if settings[1] == 0:
        scaler = MinMaxScaler()
    elif settings[1] == 1:
        scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df_reduced_strong)


#PCA for dimensionality reduction
pca = PCA(n_components=2)
if settings[0] == 1:
    df_pca = pca.fit_transform(df_scaled)
else:
    df_pca = pca.fit_transform(df_reduced_strong)
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
        if settings[0] == 1:
            tsne_results = tsne.fit_transform(df_scaled)
        else:
            tsne_results = tsne.fit_transform(df_reduced_strong)

        # Compute Silhouette Score
        if settings[0] == 1:
            silhouette_avg = silhouette_score(df_scaled, tsne_results[:, 0])  
        else:
            silhouette_avg = silhouette_score(df_reduced_strong, tsne_results[:, 0])  
        
        print(f"Perplexity: {perplexity}, Learning Rate: {lr}, Silhouette Score: {silhouette_avg:.4f}")

        if silhouette_avg > best_score:
            if settings[0] == 1:
                df_tsne = tsne.fit_transform(df_scaled)
            else:
                df_tsne = tsne.fit_transform(df_reduced_strong)
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
neighbors = 10

# Initialize K-Fold cross-validation with 10 folds
kf = KFold(n_splits=10, shuffle=True, random_state=42)

# Feature sets and target variable
X_sets = [
    df_reduced_strong.drop(columns=['Malware', 'PCA1', 'PCA2', 'TSNE1', 'TSNE2']),  # No reduction
    df_reduced_strong[['PCA1', 'PCA2']],  # PCA
    df_reduced_strong[['TSNE1', 'TSNE2']]  # t-SNE
]
Y = df_reduced_strong['Malware']

print("----------------------------------------------------------------------------------------------")
print("k-Nearest Neighbours")
print("----------------------------------------------------------------------------------------------")

best_model = None
best_accuracy = 0
best_scaler = None
best_reduction = None

for feature_set_idx, X in enumerate(X_sets):
    print(f"Feature Set {feature_set_idx + 1}: {'No Reduction' if feature_set_idx == 0 else 'PCA' if feature_set_idx == 1 else 't-SNE'}")
    
    accuracies = []
    confusion_matrices_KNN = []

    for i in range(10):
        X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)

        # Apply scaling only if scale[feature_set_idx] == 1
        if settings[0] == 1:
            X_train = scaler.fit_transform(X_train)
            X_test = scaler.transform(X_test)  # Use transform instead of fit_transform

        # Train KNN classifier
        knn = KNeighborsClassifier(n_neighbors=neighbors)
        knn.fit(X_train, y_train)

        # Make predictions and compute accuracy
        y_pred = knn.predict(X_test)
        accuracies.append(accuracy_score(y_test, y_pred))

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)

        if acc > best_accuracy:
            best_accuracy = acc
            best_model = knn
            best_reduction = feature_set_idx
            if(settings[0] == 1):
                best_scaler = scaler 


        # Store confusion matrix
        confusion_matrices_KNN.append(pd.DataFrame(
            confusion_matrix(y_test, y_pred),
            index=['Actual Yes', 'Actual No'],
            columns=['Predicted Yes', 'Predicted No']
        ))

        print(f'Accuracy: {acc:.4f}')
        print(f'Precision: {prec:.4f}')
        print(f'Recall: {rec:.4f}')
        print(f'Accuracy for KNN fold {i}: {accuracies[-1]}')

    print("----------------------------------------------------------------------------------------------")
    for i, cm in enumerate(confusion_matrices_KNN, start=1):
        print(f'Confusion Matrix for KNN Fold {i}:')
        print(cm)

    print("----------------------------------------------------------------------------------------------")
    mean_accuracy = np.mean(accuracies)
    print(f'Mean Accuracy for KNN n={neighbors}: {mean_accuracy}')
    print("----------------------------------------------------------------------------------------------")

y_val = df_validation_y
if settings[0] == 1:
    df_scaled = best_scaler.fit_transform(df_validation)

if best_reduction == 1:
    print("PCA SELECTED")
    pca = PCA(n_components=2)
    if settings[0] == 1:
        df_pca = pca.fit_transform(df_scaled)
    else:
        df_pca = pca.fit_transform(df_validation)
    df_validation['PCA1'] = df_pca[:, 0]
    df_validation['PCA2'] = df_pca[:, 1]
    
    X_val = df_validation[['PCA1', 'PCA2']]
elif best_reduction == 2:
    print("TSNE SELECTED")
    tsne = TSNE(n_components=2, perplexity=perplexity, learning_rate=lr, random_state=42, init="pca", n_iter=1000)
    if settings[0] == 1:
        tsne_results = tsne.fit_transform(df_scaled)
    else:
        tsne_results = tsne.fit_transform(df_validation)
    df_validation['TSNE1'] = tsne_results[:, 0]
    df_validation['TSNE2'] = tsne_results[:, 1]

    X_val = df_validation[['TSNE1', 'TSNE2']]
else:
    print("NO METHOD SELECTED")
    if settings[0] == 1:
        X_val = best_scaler.transform(df_validation)
    else:
        X_val = df_validation

y_val_pred = best_model.predict(X_val)
acc = accuracy_score(y_val, y_val_pred)
prec = precision_score(y_val, y_val_pred, zero_division=0)
rec = recall_score(y_val, y_val_pred, zero_division=0)

y_modified = np.where(
    (y_val_pred != y_val) & (y_val_pred != y_train.min()), 2,  # False Positive → 2
    np.where((y_val_pred != y_val) & (y_val_pred == y_train.min()), 3, y_val_pred)  # False Negative → 3
)

X_val['Malware'] = y_modified

X_val["Malware"] = X_val["Malware"].replace({
    0: "True Positive",
    1: "True Negative",
    2: "False Positive",
    3: "False Negative"
})

df_reduced_strong["Malware"] = df_reduced_strong["Malware"].replace({
    0: "True Positive",
    1: "True Negative",
    2: "False Positive",
    3: "False Negative"
})

print("VALIDATION")
print(f'Accuracy: {acc:.4f}')
print(f'Precision: {prec:.4f}')
print(f'Recall: {rec:.4f}')

if best_reduction == 1:
    plt.figure(figsize=(12, 10))
    sns.scatterplot(x='PCA1', y='PCA2', hue='Malware', data=df_reduced_strong, palette='viridis', alpha=0.5)
    sns.scatterplot(x='PCA1', y='PCA2', hue='Malware', data=X_val, palette='viridis')
    plt.title('Original vs predicted validation placement')
    plt.xlabel('PCA1')
    plt.ylabel('PCA2')
    plt.legend()
    plt.show()
elif best_reduction == 2:
    plt.figure(figsize=(12, 10))
    sns.scatterplot(x='TSNE1', y='TSNE2', hue='Malware', data=df_reduced_strong, palette='viridis', alpha=0.5)
    sns.scatterplot(x='TSNE1', y='TSNE2', hue='Malware', data=X_val, palette='viridis')
    plt.title('Original vs predicted validation placement')
    plt.xlabel('PCA1')
    plt.ylabel('PCA2')
    plt.legend()
    plt.show()
else:
    df_reduced_strong['Malware'].value_counts().plot(kind='bar', edgecolor='black')
    X_val['Malware'].value_counts().plot(kind='bar', edgecolor='green', color='green')
    plt.xlabel('Unique Values')
    plt.ylabel('Count')
    plt.title(f'Occurance of Malware')
    plt.xticks(rotation=45)
    plt.show()