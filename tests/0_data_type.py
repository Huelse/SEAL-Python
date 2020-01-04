from seal import *
import numpy as np

a = np.array([0.1, 0.3, 1.01, 0.2])
b = DoubleVector.numpy(a)  # IntVector
c = np.array(b)
print(c)
# [0.1  0.3  1.01 0.2 ]

d = IntVector(10)
print(len(d))
d[4] = 1
e = np.array(d)
print(e)
# [0 0 0 0 1 0 0 0 0 0]
