import numpy as np
import numpy as np
from scipy.interpolate import interp1d
import matplotlib.pyplot as plt 
import csv
import sys

# 1 - with indent
# 2 - without indent
# 3 - gzipped
MODE = int(sys.argv[1])
if MODE == 1:
    print("With indent")
elif MODE == 2:
    print("Without indent")
elif MODE == 3:
    print("Gzipped")
# 2900 is all dataset size
LINES_COUNTER = 2899
info_mod = 1000
print_data = 2899

def generate_curved(x, y):
    cubic_interpolation_model = interp1d(x, y, kind = "cubic")
    # Plotting the Graph
    X_=np.linspace(x.min(), x.max(), 500)
    Y_=cubic_interpolation_model(X_)
    return X_, Y_

x = np.array([e * 4 for e in range(1, LINES_COUNTER)])
 
# STIX Dataset
y_stix = []
is_first_line = True
line_counter = 1
with open("stix_results.csv", "r") as f:
    csvFile = csv.reader(f)
    for lines in csvFile:
        if is_first_line:
            is_first_line = False
            continue
        # есть сам иок + ссылка на него + количество тэгов + количество авторов
        informational_counter = 2 * (int(lines[0]) + 4) + int(lines[4]) + int(lines[5])
        y_stix.append(informational_counter * info_mod / int(lines[MODE]))
        line_counter += 1
        if line_counter == print_data:
            print("STIX informational: %s, size: %s, coefficient: %s" % (informational_counter, int(lines[MODE]), informational_counter * info_mod / int(lines[MODE])))
        if line_counter == LINES_COUNTER:
            break
X1_, Y1_ = generate_curved(x, np.array(y_stix))
plt.plot(X1_, Y1_, color='r', label="STIX")

# MISP JSON Dataset
y_misp = []
is_first_line = True
line_counter = 1
with open("misp_json_results.csv", "r") as f:
    csvFile = csv.reader(f)
    for lines in csvFile:
        if is_first_line:
            is_first_line = False
            continue
        # есть сам иок + количество тэгов
        informational_counter = int(lines[0]) + 4 + int(lines[4])
        y_misp.append(informational_counter * info_mod / int(lines[MODE]))
        line_counter += 1
        if line_counter == print_data:
            print("MISP JSON informational: %s, size: %s, coefficient: %s" % (informational_counter, int(lines[MODE]), informational_counter * info_mod / int(lines[MODE])))
        if line_counter == LINES_COUNTER:
            break
X2_, Y2_ = generate_curved(x, y_misp)
plt.plot(X2_, Y2_, color='g', label="MISP JSON")

# OpenIOC Dataset
y_openioc = []
is_first_line = True
line_counter = 1
with open("openioc_results.csv", "r") as f:
    csvFile = csv.reader(f)
    for lines in csvFile:
        if is_first_line:
            is_first_line = False
            continue
        # есть ток сам иок
        informational_counter = int(lines[0]) + 4
        y_openioc.append(informational_counter * info_mod / int(lines[MODE]))
        line_counter += 1
        if line_counter == print_data:
            print("OpenIOC informational: %s, size: %s, coefficient: %s" % (informational_counter, int(lines[MODE]), informational_counter * info_mod / int(lines[MODE])))
        if line_counter == LINES_COUNTER:
            break
X3_, Y3_ = generate_curved(x, y_openioc)
plt.plot(X3_, Y3_, color='y', label="OpenIOC")

#plt.title("Анализ информационной насыщенности STIX, MISP JSON и OpenIOC при росте количества индикаторов компрометации")
plt.xlabel("Количество индикаторов компрометации")
plt.ylabel("Коэффициент эффективности, 10e3")
plt.legend()
plt.show()

