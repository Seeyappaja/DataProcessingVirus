import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score

df = pd.read_csv('dataset_malwares.csv')

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
df_reduced = df.drop(columns=['Name'])

correlation_matrix = df_reduced.corr()
# Visualize the correlation matrix using a heatmap
# plt.figure(figsize=(12, 10))
# sns.heatmap(correlation_matrix, annot=True, fmt=".2f", cmap='coolwarm')
# plt.title('Correlation Matrix')
#plt.show()

threshold = 0.5
strong_correlations = correlation_matrix[correlation_matrix.abs() > threshold]
strong_pairs = strong_correlations.unstack().dropna().sort_values(ascending=False)
strong_pairs = strong_pairs[strong_pairs < 1]
#print("Strongly correlated feature pairs:")
#print(strong_pairs)

strong_pairs_columns = set()
for pair in strong_pairs.index:
    strong_pairs_columns.add(pair[0])
    strong_pairs_columns.add(pair[1])
df_reduced_strong = df[list(strong_pairs_columns)]

# Standardize the data
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df_reduced_strong)

# Apply K-Means clustering
kmeans = KMeans(n_clusters=3, random_state=42)
df_reduced_strong['Cluster'] = kmeans.fit_predict(df_scaled)

# PCA for dimensionality reduction
pca = PCA(n_components=2)
df_pca = pca.fit_transform(df_scaled)
df_reduced_strong['PCA1'] = df_pca[:, 0]
df_reduced_strong['PCA2'] = df_pca[:, 1]

# Plot PCA results with centroids
plt.figure(figsize=(12, 10))
sns.scatterplot(x='PCA1', y='PCA2', hue='Cluster', data=df_reduced_strong, palette='viridis')
plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1], s=300, c='red', marker='X', label='Centroids')
plt.title('K-Means Clustering with PCA')
plt.xlabel('PCA1')
plt.ylabel('PCA2')
plt.legend()
plt.show()

# t-SNE for dimensionality reduction
tsne = TSNE(n_components=2, random_state=42)
df_tsne = tsne.fit_transform(df_scaled)
df_reduced_strong['TSNE1'] = df_tsne[:, 0]
df_reduced_strong['TSNE2'] = df_tsne[:, 1]

# Plot t-SNE results with centroids
plt.figure(figsize=(12, 10))
sns.scatterplot(x='TSNE1', y='TSNE2', hue='Cluster', data=df_reduced_strong, palette='viridis')
plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1], s=300, c='red', marker='X', label='Centroids')
plt.title('K-Means Clustering with t-SNE')
plt.xlabel('TSNE1')
plt.ylabel('TSNE2')
plt.legend()
plt.show()

# Silhouette Analysis
silhouette_avg = silhouette_score(df_scaled, df_reduced_strong['Cluster'])
print(f'Silhouette Score: {silhouette_avg}')

# Visualize the clusters with centroids
for pair in strong_pairs.index:
    plt.figure(figsize=(12, 10))
    sns.scatterplot(x=pair[0], y=pair[1], hue=df_reduced_strong['Cluster'], data=df_reduced_strong, palette='viridis', s=100, alpha=0.7, edgecolor='w', linewidth=0.5)
    plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1], s=300, c='red', marker='X', label='Centroids')
    plt.title(f'K-Means Clustering: {pair[0]} vs {pair[1]}')
    plt.xlabel(pair[0])
    plt.ylabel(pair[1])
    plt.legend()
    plt.show()