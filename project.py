import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

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
df_reduced = df[high_var_columns]

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
df_reduced_strong = df_reduced[list(strong_pairs_columns)]

# Assuming 'Malware' is the target variable
X = df_reduced_strong.drop(columns=['Malware'])
y = df_reduced_strong['Malware']

rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X, y)

feature_importances = rf.feature_importances_
features = X.columns

# Visualize feature importances
plt.figure(figsize=(12, 10))
sns.barplot(x=feature_importances, y=features)
plt.title('Feature Importances')
plt.xlabel('Importance')
plt.ylabel('Features')
plt.show()

# Standardize the data
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df_reduced_strong)

# Apply K-Means clustering
kmeans = KMeans(n_clusters=3, random_state=42)
df_reduced_strong['Cluster'] = kmeans.fit_predict(df_scaled)

# Visualize the clusters
for pair in strong_pairs.index:
    plt.figure(figsize=(12, 10))
    sns.scatterplot(x=df_reduced_strong[pair[0]], y=df_reduced_strong[pair[1]], hue=df_reduced_strong['Cluster'], palette='viridis')
    plt.title('K-Means Clustering')
    plt.xlabel(pair[0])
    plt.ylabel(pair[1])
    plt.show()
