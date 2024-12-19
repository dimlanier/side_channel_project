import numpy as np
import matplotlib.pyplot as plt

# Replace 'output.dat' with your filename and adjust dtype as needed
data = np.fromfile('output-data.out', dtype=np.float32)

    
plt.plot(data)
plt.xlabel('Sample Index')
plt.ylabel('Amplitude')
plt.title('Recorded Data')
plt.show()