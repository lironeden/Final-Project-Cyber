import subprocess, ipaddress, socket, threading, Queue, sys, requests, random, tkFont, tkMessageBox, tkFont
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e
from Tkinter import *
DISTANCE_IP_TO_SUB = 41  # Tested an checked
ERROR = "error"
class ScanOpenPortsThr(threading.Thread):  # Create a custom thread
    def __init__(self, queue, selection, active_connections):
        threading.Thread.__init__(self)  # Call the threading initial function
        self.queue = queue  # define a queue that will transfer information from the thread
        self.selection = selection  # The current selection from the Listbox object
        self.active_connections = active_connections
    def run(self):
        """
        override the 'run' function from the threading.Thread class
        """
        active_connections = self.active_connections
        threads_list = []
        open_ports = []
        ip = self.selection
        if ip != ():  # if there is any selection
            ip = active_connections[int(ip[0])][0]  # The ip's in the listbox are in the same order such as /
            # in the active connections
            print ip  # Debugging(will be deleted)
            def thr_func(port, open_ports):
                """
                Create a thread function that will send fast tcp syn
                """
                to_send = IP(dst = ip)/TCP(dport = port, sport = random.randint(10000, 20000))
                ans = sr1(to_send, timeout = 5, verbose=False)
                if ans != None and ans[TCP].flags == 18:  # If the flags are syn+ack(18 in int)
                    open_ports.append(port)
            for prt in range(1, 1000):  # Scan the first 1000 ports
                temp_thr = threading.Thread(target=thr_func, args=(prt, open_ports,))
                threads_list.append(temp_thr)
                temp_thr.start()
            for thr in threads_list:
                thr.join()
            print open_ports
            self.queue.put(str(open_ports))  # put the open ports in the queue
        else:
            self.queue.put(ERROR)  # return error if no ip selected
def get_all_ip():
    """
    This function returns all the ip addresses that possible to be created by ip and subnet
    """
    proc = subprocess.check_output("ipconfig")  # Runs the "ipconfig" command in windows command lines
    a = str(proc)
    ip = socket.gethostbyname(socket.gethostname())  # Get the local ip address
    try:
        validate = socket.socket()
        validate.connect(("www.google.com", 80))
        val_ip = validate.getsockname()[0]
        if val_ip != ip:
            ip = val_ip
    except:
        pass
    subnet = ""
    ip_loc = a.find(ip)  # Finds the ip address at the ipconfig output
    sub_loc = ip_loc + len(ip) + DISTANCE_IP_TO_SUB  # calculates the first char of the subnet address
    tav = "5"  # declaration
    i = 0  # indexer
    while tav.isdigit() or tav == ".":
        tav = a[sub_loc + i]
        if not tav.isdigit() and not tav == ".":  # Check again for the end of the loop
            break
        subnet += tav  # Adds the relevant output of the "ipconfig" to the subnet parameter
        i += 1
    my_network = ipaddress.IPv4Network(unicode(ip + "/" + subnet), strict=False)  # Creates a new ip object
    if my_network.prefixlen > 10:  # If the network is unlikely big
        all_ip = [str(i) for i in my_network]  # Get all the possible ip addresses in my local network
        return all_ip
    else:
        all_ip = []
        ip = ip[:ip.rfind(".")]
        for i in xrange(1, 255):
            all_ip.append(ip + "." + str(i))
        return all_ip
def f(packet):
    """
    This function is the filter function for the "sniff" method in scapy
    """
    if ARP in packet:
        return packet[ARP].op == 2
    if ICMP in packet:
        return packet[ICMP].type == 0
    return False
def thr(queue):
    """
    This function is a thread function that will sniff packets for 30 sec and filter the relevant ones
    """
    pkts = sniff(lfilter = f, timeout=35)
    queue.put(pkts)  # Put the packets list inside a queue in order to pull it from the main() func
def send_slow(ip):
    """
    This function is also a thread func because "send" method is slow
    so we create 255 threads to short the time
    """
    send(IP(dst = ip)/ICMP(), count = 4, verbose=False)
def thr_open_ports(selection, window, active_connections, queue, check=False):
    """
    This function will start a thread so that the Tkinter mainloop won't stuck during scan open ports runtime
    Check is parameter that will allow to know which part of the function to run
    """
    if not check:
        tkMessageBox.showinfo('Open Ports', "Please wait patiently! to start scanning press OK")
        ScanOpenPortsThr(queue, selection, active_connections).start()
        window.after(100, lambda:check_queue(window, queue))
    else:  # tkMessagebox able to run *only* at the function called in the button!
        if selection == "error":
            tkMessageBox.showerror('Error', "You must select connected device from the list!")
        else:
            tkMessageBox.showinfo('Open Ports', str(selection))
    print "worked!"
def check_queue(window, queue):
    try:
        msg = queue.get(0)  # Info from the thread
        thr_open_ports(str(msg), window, None, None, True)  # Call the function again because tkMessagebox can only run at the /
        # same function called at the button!
    except:
        window.after(100, lambda :check_queue(window, queue))  # Return information to the mainloop so it won't freeze.
def more_info_mes(active_connections, ip_list):
    loc = ip_list.curselection()
    if loc != ():
        index = int(loc[0])
        ip = active_connections[index][0]
        mac = active_connections[index][1]
        name = active_connections[index][2]
        mac_vend = active_connections[index][3]
        tkMessageBox.showinfo('Information on device', "The device ip: " + str(ip) + "\n" + "The device mac address: "
                                                       + str(mac) + "\n" + " The device name in the local network(if there is): " + str(name) + "\n" + " The device's mac vendor is: " + str(mac_vend))
    else:
        tkMessageBox.showerror("Error", "You must select connected device from the list!")
def main():
    active_connections = []  # This parameter contains list of all active connections ip's, mac and hostnames
    queue = Queue.Queue()
    icmp_threads = []
    packets_arp = []
    sniff_thr = threading.Thread(target = thr, args=(queue,))
    window = Tk()
    window.geometry("800x500")
    window.title("Liron's project")
    tkMessageBox.showinfo('Attention!', 'Please notice it is Windows OS program only!')
    temp_lable = Label(window, text="Loading, Please Wait! ...", anchor = CENTER, height = 10)
    temp_lable.pack()
    window.update_idletasks()
    window.update()
    for ip in get_all_ip():
        pkt1 = Ether(dst = "ff:ff:ff:ff:ff:ff", type = 2054)/ARP(pdst = ip)  # Create arp "who has" packet
        packets_arp.extend([pkt1] * 3)
        temp_thread = threading.Thread(target = send_slow, args=(ip,))
        icmp_threads.append(temp_thread)
    sniff_thr.start()  # Start sniffing before sending all the packets
    sendp(packets_arp, verbose=False)  # Send all the arp packets
    for t in icmp_threads:
        t.start()  # Send all the icmp packets
    for t in icmp_threads:
        t.join()  # Than wait until each will finish
    sniff_thr.join()  # also the sniff thread
    n = queue.get()  # Get all the relevant packets that captured
    for i in n:
        if i == None:
            continue
        elif ICMP in i:
            active_connections.append((i[IP].src, i[Ether].src, None, None))
        elif ARP in i:
            active_connections.append((i[ARP].psrc, i[Ether].src, None, None))
    active_connections = list(set(active_connections))
    for i, connection in enumerate(active_connections):
        name = socket.getfqdn(connection[0])
        print name
        try:
            r = requests.get("http://macvendors.co/api/" + connection[1])
            print r
            ans = r.json()
            vendor = ans["result"]["company"]
        except:
            vendor = None
        b = list(connection)
        b[3] = str(vendor)
        if name != connection[0]:
            b[2] = name
        active_connections[i] = tuple(b)
    print active_connections
    temp_lable.pack_forget()
    fnt = tkFont.Font(size=10)
    ip_list = Listbox(window, height =31 , width = 80, exportselection=0, font = fnt)
    ip_list.pack(side=LEFT, anchor = W)
    scrollbary = Scrollbar(window, orient="vertical",command=ip_list.yview)
    scrollbary.pack(side=LEFT, fill=Y)
    ip_list.config(yscrollcommand=scrollbary.set)
    for i in active_connections:
        ip = i[0]
        ip_list.insert(END, " IP: " + str(ip) + " for more information press 'More Info' button")
    scan_ports = Button(window, text="Scan Open Ports", command= lambda: thr_open_ports(ip_list.curselection(), window, active_connections, queue), height = 10, width = 20)
    more_info = Button(window, text = "More Info", command = lambda : more_info_mes(active_connections, ip_list), height = 10, width = 20)
    helv36 = tkFont.Font(family='Helvetica', size=12, weight='bold')
    scan_ports["font"] = helv36
    more_info["font"] = helv36
    scan_ports.place(x = 580)
    more_info.place(x = 580, y= 200)
    window.after(200, lambda:check_queue(window, queue))
    window.mainloop()
if __name__ == "__main__":
    main()