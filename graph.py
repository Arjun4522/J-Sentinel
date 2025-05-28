import json
import networkx as nx
import matplotlib.pyplot as plt

# Load your JSON file
with open('codegraph.json') as f:
    data = json.load(f)

# Create a directed graph
G = nx.DiGraph()

# Add nodes
for node in data['nodes']:
    label = f"{node['type']}:{node.get('name', node['id'])}"
    G.add_node(node['id'], label=label, type=node['type'])

# Add edges
for edge in data['edges']:
    G.add_edge(edge['source'], edge['target'], label=edge['type'])

# Get labels for visualization
node_labels = {n: G.nodes[n]['label'] for n in G.nodes}
edge_labels = {(u, v): d['label'] for u, v, d in G.edges(data=True)}

# Draw the graph
plt.figure(figsize=(18, 12))
pos = nx.spring_layout(G, seed=42, k=0.5)
nx.draw(G, pos, labels=node_labels, with_labels=True, node_size=1500, node_color="skyblue", arrows=True)
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='red')
plt.title("Parsed Code Graph")
plt.axis('off')
plt.show()
