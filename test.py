import matplotlib.pyplot as plt
import pandas as pd

# Define the tasks and their start/end dates
tasks = {
    'Task': [
        'Setup and Initialization',
        'GUI Layout',
        'Function Implementations',
        'Event Handlers',
        'Testing and Debugging',
        'Documentation and Help'
    ],
    'Start': [
        '2024-07-05',  # Start date for the project
        '2024-07-12',  # After Setup and Initialization
        '2024-07-19',  # After GUI Layout
        '2024-07-26',  # After Function Implementations
        '2024-08-02',  # After Event Handlers
        '2024-08-05'   # After Testing and Debugging
    ],
    'End': [
        '2024-07-11',  # End date for Setup and Initialization
        '2024-07-18',  # End date for GUI Layout
        '2024-07-25',  # End date for Function Implementations
        '2024-08-01',  # End date for Event Handlers
        '2024-08-08',  # End date for Testing and Debugging
        '2024-08-12'   # End date for Documentation and Help
    ]
}

# Create a DataFrame
df = pd.DataFrame(tasks)

# Convert dates to datetime
df['Start'] = pd.to_datetime(df['Start'])
df['End'] = pd.to_datetime(df['End'])

# Plotting the Gantt chart
fig, ax = plt.subplots(figsize=(8, 6))  # Adjusted figure size to allow more space

# Creating the bars
for i, task in enumerate(df['Task']):
    ax.barh(task, (df['End'][i] - df['Start'][i]).days, left=df['Start'][i])

# Formatting the chart
ax.set_xlabel('Dates')
ax.set_ylabel('Tasks')
ax.set_title('Gantt Chart for Firewall Configuration Tool')
ax.grid(True)

# Adjust the margins to make sure labels fit
plt.subplots_adjust(left=0.25, right=0.95, top=0.95, bottom=0.1)

# Setting the x-axis ticks to show weekly intervals
plt.xticks(pd.date_range(start='2024-07-05', end='2024-08-12', freq='W'))

plt.show()
