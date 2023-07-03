import tkinter
from tkinter import Button
from tkinter import font
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import subprocess
import os
import re
from tkinter import END
import ipaddress
import csv
# 点击按钮后的函数
# 检测ip地址的合法性
def is_valid_ip_address(ip_address_str):
    try:
        ipaddress.IPv4Address(ip_address_str)
        return True
    except ipaddress.AddressValueError:
        return False
def export_to_csv(treeview):
    # 获取所有行和列的数据
    headings = []
    rows = []
    for column in treeview["columns"]:
        headings.append(column)
    for row in treeview.get_children():
        current_row = []
        for column in headings:
            current_row.append(treeview.item(row)["values"][headings.index(column)])
        rows.append(current_row)
    file_path = filedialog.askdirectory()
    # 创建并写入 CSV 文件
    if file_path:
        # 拼接文件路径
        file_path = os.path.join(file_path, 'table.csv')
        with open(file_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headings)
            writer.writerows(rows)
        messagebox.showinfo(parent=root, title='succedd', message='导出成功')
def input_csv(treeview):
    file_path = filedialog.askopenfilename(defaultextension='.csv')
    # 如果用户选择了文件
    if file_path:
        # 获取已有的行数
        rows = treeview.get_children()
        row_count = len(rows)
        # 创建一个空列表
        data = []
        # 如果用户选择了文件
        if file_path:
            # 获取已有的行数
            rows = treeview.get_children()
            row_count = len(rows)
            # 从CSV文件的第二行开始读取数据，将数据添加到treeview中
            with open(file_path, 'r') as f:
                reader = csv.reader(f)
                headers = next(reader)  # 跳过第一行数据
                i = 0
                for row in reader:
                    treeview.insert('', row_count + i, values=row)
                    i += 1
                    saddr = row[1]
                    sport = row[2]
                    daddr = row[3]
                    dport = row[4]
                    interface = row[5]
                    time_begin = row[6]
                    time_end = row[7]
                    protocol = row[8]
                    subtype = row[9]
                    if re.search('.*any.*', saddr):
                        saddr = ' '
                    else:
                        saddr = ' -x ' + saddr
                    if re.search('.*any.*', daddr):
                        daddr = '  '
                    else:
                        daddr = ' -y ' + daddr
                    if re.search('.*any.*', sport):
                        sport = ' '
                    else:
                        sport = ' -m ' + daddr
                    if re.search('.*any.*', dport):
                        dport=' '
                    else:
                        dport = ' -n ' + dport
                    if re.search(r'\d' ,time_begin):
                        time_begin = ' -b ' + time_begin
                    else:
                        time_begin = ' '
                    if re.search(r'\d',time_end):
                        time_end = ' -e ' + time_end
                    else:
                        time_end = ' '
                    if re.search('.*any.*', interface):
                        interface = ''
                    else:
                        interface = ' -i ' + interface
                    if re.search('.*any.*', subtype):
                        subtype = ' '
                    else:
                        subtype = ' -t '+ subtype
                    command = "./configure" + " -p " + protocol + saddr+ sport + daddr + dport + time_begin + time_end + interface + subtype
                    print(command)
                    flag = os.system(command)
                    if flag == 0:
                        messagebox.showinfo(parent=root, title="导入成功", message="导入成功")
                    else:
                        messagebox.showinfo(parent=root, title="导入失败", message="导入失败")



def add_rules ():
    add=tkinter.Tk()
    add.title("add the rules")
    add.geometry("800x400+400+200")
    # 设置输入框
    add_SADDR = tkinter.Text(add, height=2, width=30)
    add_SADDR.place(x = 100, y=20)
    add_DADDR = tkinter.Text(add, height=2, width=30)
    add_DADDR.place(x=500, y=20)
    add_SPORT = tkinter.Text(add, height=2, width=30)
    add_SPORT.place(x=100, y=80)
    add_DPORT = tkinter.Text(add, height=2, width=30)
    add_DPORT.place(x=500, y=80)
    # 设置时间和协议的下拉框
    time_flag_value = ['是','否']
    time_var = tkinter.StringVar(add)
    time_var.set(time_flag_value[0])
    time_flag = tkinter.OptionMenu(add,time_var,*time_flag_value)
    time_flag.config(width=4)
    time_flag.place(x = 100 ,y= 140)
    protocol_value = ['icmp' ,'tcp','udp']
    protocol_var = tkinter.StringVar(add)
    protocol_var.set(protocol_value[0])
    protocol = tkinter.OptionMenu(add, protocol_var,*protocol_value)
    protocol.config(width=7)
    protocol.place(x = 500,y=140)
    # 设置开始时间和结束时间
    time_begin = tkinter.Text(add, height=2, width=30)
    time_begin.place(x=100, y=200)
    time_end = tkinter.Text(add, height=2, width=30)
    time_end.place(x=500, y=200)
    icmp_subtype = tkinter.Text(add, height=2, width=30)
    icmp_subtype.place(x= 100 , y=260)
    interface = tkinter.Text(add, height=2, width=30)
    interface.place(x= 500 ,y=260)
    # 设置行数
    def add_get():
        global number
        # 检验输入合理性
        check = 1
        DADDR_text = add_DADDR.get('1.0', 'end-1c').strip()
        SADDR_text = add_SADDR.get('1.0', 'end-1c').strip()
        DPORT_text = add_DPORT.get('1.0', 'end-1c').strip()
        SPORT_text = add_SPORT.get('1.0', 'end-1c').strip()
        time_flag_text = time_var.get().strip()
        protocol_text = protocol_var.get().strip()
        time_begin_text = time_begin.get('1.0', 'end-1c').strip()
        time_end_text = time_end.get('1.0', 'end-1c').strip()
        icmp_subtype_text = icmp_subtype.get('1.0', 'end-1c').strip()
        interface_text = interface.get('1.0', 'end-1c').strip()
        if not is_valid_ip_address(DADDR_text) and  re.search(r"\d", DADDR_text):
            check=0
            messagebox.showinfo(parent=add, title="error", message="输入的目标地址不合理")
        if not is_valid_ip_address(SADDR_text) and  re.search(r"\d", SADDR_text):
            check=0
            messagebox.showinfo(parent=add, title="error", message="输入的源地址不合理")
        if  not re.search(r"\d", DADDR_text):
            DADDR_text = "  " + DADDR_text
        else:
            DADDR_text_value = DADDR_text
            DADDR_text = " -y " + DADDR_text
        if  not re.search(r"\d", SADDR_text):
            SADDR_text = "  " + SADDR_text
        else:
            SADDR_text_value = SADDR_text
            SADDR_text = " -x " + SADDR_text
        if  not re.search(r"\d", SPORT_text):
            SPORT_text = "  " + SPORT_text
        else:
            SPORT_text_value = SPORT_text
            SPORT_text = " -m " + SPORT_text
        if not re.search(r"\d", DPORT_text):
            DPORT_text = " " + DPORT_text
        else:
            DPORT_text_value = DPORT_text
            DPORT_text = " -n " + DPORT_text
        if not re.search(r"\d" , time_begin_text):
            time_begin_text = " " + time_begin_text
        else:
            time_begin_value = time_begin_text
            time_begin_text = " -b " + time_begin_text
        if not re.search(r"\d", time_end_text):
            time_end_text = " " + time_end_text
        else:
            time_end_value = time_end_text
            time_end_text = " -e " + time_end_text
        if not re.search(r"\d" , icmp_subtype_text):
            icmp_subtype_text = " " + icmp_subtype_text
        else:
            icmp_subtype_value = icmp_subtype_text
            icmp_subtype_text = " -t " + icmp_subtype_text
        if not re.search(r"\d", interface_text):
            interface_text = " " + interface_text
        else:
            interface_value = interface_text
            interface_text = " -i " + interface_text
        if check == 1:
            command = "./configure" + " -p " + protocol_text + SADDR_text + SPORT_text + DADDR_text + DPORT_text + time_begin_text + time_end_text + interface_text + icmp_subtype_text
            flag = os.system(command)
            if flag == 0:
                messagebox.showinfo(parent=add,title="添加成功",message="添加成功")
                # 把添加的规则插入图表
                if not re.search(r"\d", DADDR_text):
                    DADDR_text = " any " + DADDR_text
                else:
                    DADDR_text = DADDR_text_value
                if not re.search(r"\d", SADDR_text):
                    SADDR_text = " any " + SADDR_text
                else:
                    SADDR_text = " " + SADDR_text_value
                if not re.search(r"\d", SPORT_text):
                    SPORT_text = " any " + SPORT_text
                else:
                    SPORT_text = " " + SPORT_text_value
                if not re.search(r"\d", DPORT_text):
                    DPORT_text = " any " + DPORT_text
                else:
                    DPORT_text = "  " + DPORT_text_value
                if not re.search(r"\d", icmp_subtype_text):
                    icmp_subtype_text = " any " + icmp_subtype_text
                else:
                    icmp_subtype_text = " " +icmp_subtype_value
                if not re.search(r"\d", interface_text):
                    interface_text = " any " + interface_text
                else:
                    interface_text = "  " + interface_value
                rule = [number, SADDR_text, SPORT_text, DADDR_text, DPORT_text, interface_text, time_begin_text, time_end_text, protocol_text,icmp_subtype_text]
                number += 1
                table.insert('', END, values=rule)
            else :
                messagebox.showinfo(parent=add,title="error" ,message= "添加失败,请检查你的输入")

    # set the labels
    SADDR_label = tkinter.Label(add, text = '源地址:')
    SADDR_label.config(font=module)
    SADDR_label.place(x=35, y=23)
    DADDR_label = tkinter.Label(add, text='目的地址:')
    DADDR_label.config(font=module)
    DADDR_label.place(x=410, y=23)
    SPORT_label = tkinter.Label(add, text='源端口号:')
    SPORT_label.config(font=module)
    SPORT_label.place(x=20, y=83)
    DPORT_label = tkinter.Label(add, text='目的端口号:')
    DPORT_label.config(font=module)
    DPORT_label.place(x=400, y=83)
    time_flag_label = tkinter.Label(add ,text = '时间过滤:',font=("Arial", 10))
    time_flag_label.place(x=30, y=145)
    protocol_label = tkinter.Label(add, text='协议名称:' ,font=("Arial", 10))
    protocol_label.place(x=435 , y= 145)
    time_begin_label = tkinter.Label(add,text='开始时间:',font=("Arial", 10))
    time_begin_label.place(x=30, y=200)
    time_end_label = tkinter.Label(add, text='结束时间:', font=("Arial", 10))
    time_end_label.place(x=430, y=200)
    icmp_subtype_label = tkinter.Label(add, text="icmp子类型", font=("Arial", 10))
    icmp_subtype_label.place(x=30, y=260)
    interface_lable = tkinter.Label(add, text="网络接口",font=("Arial", 10))
    interface_lable.place(x=430,y=260)
    add_OK = Button(add, text="添加规则", font=("Arial", 10), command=add_get)
    add_OK.place(x=700, y=300)
    add.mainloop()
def remove_rules (treeview):
    remove = tkinter.Tk()
    remove.title("remove the rules")
    remove.geometry("800x400+400+200")
    remove.mainloop()
    rules = []
    number_rows = len(treeview.get_children())
    rules_select = tkinter.Label(remove, text="输入要删除的规则:", font=("Arial", 10))
    rules_select.place(x=70, y=70)
    for number in range(number_rows):
        rules.append('规则' + str(number + 1))
    rules_option = tkinter.StringVar()
    rule_select = ttk.Combobox(remove, textvariable=rules_option, values=rules, width=10, height=10)
    sure = tkinter.Button(remove, text="确定", font=("Arial", 10), command=modify_rule)
    sure.place(x=300, y=170)
    rule_select.place(x=200, y=70)

def modify_rules(treeview):
    check_rules = tkinter.Tk()
    rules = []
    check_rules.title('choose the rules')
    check_rules.geometry("400x200+400+200")
    number_rows = len(treeview.get_children())
    rules_select = tkinter.Label(check_rules,text="输入要修改的规则:",font=("Arial", 10))
    rules_select.place(x=70,y=70)
    for number in range(number_rows):
        rules.append('规则' + str(number + 1))
    def modify_rule():
        check_rules.destroy()
        modify = tkinter.Tk()
        modify.title('modify this rule')
        modify.geometry("800x400+400+200")
        # 设置输入框
        modify_SmodifyR = tkinter.Text(modify, height=2, width=30)
        modify_SmodifyR.place(x=100, y=20)
        modify_DmodifyR = tkinter.Text(modify, height=2, width=30)
        modify_DmodifyR.place(x=500, y=20)
        modify_SPORT = tkinter.Text(modify, height=2, width=30)
        modify_SPORT.place(x=100, y=80)
        modify_DPORT = tkinter.Text(modify, height=2, width=30)
        modify_DPORT.place(x=500, y=80)
        # 设置时间和协议的下拉框
        time_flag_value = ['是', '否']
        time_var = tkinter.StringVar(modify)
        time_var.set(time_flag_value[0])
        time_flag = tkinter.OptionMenu(modify, time_var, *time_flag_value)
        time_flag.config(width=4)
        time_flag.place(x=100, y=140)
        protocol_value = ['icmp', 'tcp', 'udp']
        protocol_var = tkinter.StringVar(modify)
        protocol_var.set(protocol_value[0])
        protocol = tkinter.OptionMenu(modify, protocol_var, *protocol_value)
        protocol.config(width=7)
        protocol.place(x=500, y=140)
        # 设置开始时间和结束时间
        time_begin = tkinter.Text(modify, height=2, width=30)
        time_begin.place(x=100, y=200)
        time_end = tkinter.Text(modify, height=2, width=30)
        time_end.place(x=500, y=200)
        icmp_subtype = tkinter.Text(modify, height=2, width=30)
        icmp_subtype.place(x=100, y=260)
        interface = tkinter.Text(modify, height=2, width=30)
        interface.place(x=500, y=260)

        # 设置行数
        def modify_get():
            global number
            # 检验输入合理性
            check = 1
            DmodifyR_text = modify_DmodifyR.get('1.0', 'end-1c').strip()
            SmodifyR_text = modify_SmodifyR.get('1.0', 'end-1c').strip()
            DPORT_text = modify_DPORT.get('1.0', 'end-1c').strip()
            SPORT_text = modify_SPORT.get('1.0', 'end-1c').strip()
            time_flag_text = time_var.get().strip()
            protocol_text = protocol_var.get().strip()
            time_begin_text = time_begin.get('1.0', 'end-1c').strip()
            time_end_text = time_end.get('1.0', 'end-1c').strip()
            icmp_subtype_text = icmp_subtype.get('1.0', 'end-1c').strip()
            interface_text = interface.get('1.0', 'end-1c').strip()
            if not is_valid_ip_address(DmodifyR_text) and re.search(r"\d", DmodifyR_text):
                check = 0
                messagebox.showinfo(parent=modify, title="error", message="输入的目标地址不合理")
            if not is_valid_ip_address(SmodifyR_text) and re.search(r"\d", SmodifyR_text):
                check = 0
                messagebox.showinfo(parent=modify, title="error", message="输入的源地址不合理")
            if not re.search(r"\d", DmodifyR_text):
                DmodifyR_text = "  " + DmodifyR_text
            else:
                DmodifyR_text_value = DmodifyR_text
                DmodifyR_text = " -y " + DmodifyR_text
            if not re.search(r"\d", SmodifyR_text):
                SmodifyR_text = "  " + SmodifyR_text
            else:
                SmodifyR_text_value = SmodifyR_text
                SmodifyR_text = " -x " + SmodifyR_text
            if not re.search(r"\d", SPORT_text):
                SPORT_text = "  " + SPORT_text
            else:
                SPORT_text_value = SPORT_text
                SPORT_text = " -m " + SPORT_text
            if not re.search(r"\d", DPORT_text):
                DPORT_text = " " + DPORT_text
            else:
                DPORT_text_value = DPORT_text
                DPORT_text = " -n " + DPORT_text
            if not re.search(r"\d", time_begin_text):
                time_begin_text = " " + time_begin_text
            else:
                time_begin_value = time_begin_text
                time_begin_text = " -b " + time_begin_text
            if not re.search(r"\d", time_end_text):
                time_end_text = " " + time_end_text
            else:
                time_end_value = time_end_text
                time_end_text = " -e " + time_end_text
            if not re.search(r"\d", icmp_subtype_text):
                icmp_subtype_text = " " + icmp_subtype_text
            else:
                icmp_subtype_value = icmp_subtype_text
                icmp_subtype_text = " -t " + icmp_subtype_text
            if not re.search(r"\d", interface_text):
                interface_text = " " + interface_text
            else:
                interface_value = interface_text
                interface_text = " -i " + interface_text
            if check == 1:
                command = "./configure" + " -p " + protocol_text + SmodifyR_text + SPORT_text + DmodifyR_text + DPORT_text + time_begin_text + time_end_text + interface_text + icmp_subtype_text
                flag = os.system(command)
                if flag == 0:
                    messagebox.showinfo(parent=modify, title="添加成功", message="添加成功")
                    # 把添加的规则插入图表
                    if not re.search(r"\d", DmodifyR_text):
                        DmodifyR_text = " any " + DmodifyR_text
                    else:
                        DmodifyR_text = DmodifyR_text_value
                    if not re.search(r"\d", SmodifyR_text):
                        SmodifyR_text = " any " + SmodifyR_text
                    else:
                        SmodifyR_text = " " + SmodifyR_text_value
                    if not re.search(r"\d", SPORT_text):
                        SPORT_text = " any " + SPORT_text
                    else:
                        SPORT_text = " " + SPORT_text_value
                    if not re.search(r"\d", DPORT_text):
                        DPORT_text = " any " + DPORT_text
                    else:
                        DPORT_text = "  " + DPORT_text_value
                    if not re.search(r"\d", icmp_subtype_text):
                        icmp_subtype_text = " any " + icmp_subtype_text
                    else:
                        icmp_subtype_text = " " + icmp_subtype_value
                    if not re.search(r"\d", interface_text):
                        interface_text = " any " + interface_text
                    else:
                        interface_text = "  " + interface_value
                    rule = [number, SmodifyR_text, SPORT_text, DmodifyR_text, DPORT_text, interface_text,
                            time_begin_text, time_end_text, protocol_text, icmp_subtype_text]
                    number += 1
                    table.insert('', END, values=rule)
                else:
                    messagebox.showinfo(parent=modify, title="error", message="添加失败,请检查你的输入")

        # set the labels
        SmodifyR_label = tkinter.Label(modify, text='源地址:')
        SmodifyR_label.config(font=module)
        SmodifyR_label.place(x=35, y=23)
        DmodifyR_label = tkinter.Label(modify, text='目的地址:')
        DmodifyR_label.config(font=module)
        DmodifyR_label.place(x=410, y=23)
        SPORT_label = tkinter.Label(modify, text='源端口号:')
        SPORT_label.config(font=module)
        SPORT_label.place(x=20, y=83)
        DPORT_label = tkinter.Label(modify, text='目的端口号:')
        DPORT_label.config(font=module)
        DPORT_label.place(x=400, y=83)
        time_flag_label = tkinter.Label(modify, text='时间过滤:', font=("Arial", 10))
        time_flag_label.place(x=30, y=145)
        protocol_label = tkinter.Label(modify, text='协议名称:', font=("Arial", 10))
        protocol_label.place(x=435, y=145)
        time_begin_label = tkinter.Label(modify, text='开始时间:', font=("Arial", 10))
        time_begin_label.place(x=30, y=200)
        time_end_label = tkinter.Label(modify, text='结束时间:', font=("Arial", 10))
        time_end_label.place(x=430, y=200)
        icmp_subtype_label = tkinter.Label(modify, text="icmp子类型", font=("Arial", 10))
        icmp_subtype_label.place(x=30, y=260)
        interface_lable = tkinter.Label(modify, text="网络接口", font=("Arial", 10))
        interface_lable.place(x=430, y=260)
        modify_OK = Button(modify, text="添加规则", font=("Arial", 10), command=modify_get)
        modify_OK.place(x=700, y=300)
        modify.mainloop()

    rules_option = tkinter.StringVar()
    rule_select = ttk.Combobox(check_rules,textvariable=rules_option,values=rules,width=10,height=10)
    sure = tkinter.Button(check_rules,text="确定",font=("Arial", 10),command=modify_rule)
    sure.place(x=300,y= 170)
    rule_select.place(x=200, y=70)
    check_rules.mainloop()




def check_log ():
    check_log = tkinter.Tk()
    check_log.title("系统日志")
    check_log.geometry("800x400+400+200")
    dmesg = tkinter.Text(check_log,height=40,width=90)
    dmesg.pack()
    result = subprocess.run('dmesg | tail -n 20 ', shell=True, capture_output=True, text=True)
    dmesg.insert(tkinter.END, result.stdout)
    check_log.mainloop()
def run_project ():
    run_flag = os.system('insmod mod_firewall.ko ')
    if run_flag == 0 :
        messagebox.showinfo(parent=root, title="开启防火墙", message="开启防火墙")
    else :
        messagebox.showinfo(parent=root, title="过滤失败", message="error")
def stop_project ():
    stop_flag = os.system('rmmod mod_firewall.ko')
    if stop_flag == 0 :
        messagebox.showinfo(parent=root, title="关闭防火墙", message="关闭防火墙")
        obj = table.get_children()  # 获取所有对象
        for o in obj:
            table.delete(o)  # 删除对象
    else :
        messagebox.showinfo(parent=root, title="停止失败", message="error")
# 开始主函数
number = 1
root=tkinter.Tk()
root.title("set the rules")
# set the size
root.geometry("1000x450+300+200")
# set the buttons
module = font.Font(family='Helvetica', size=12)
modify_rules_button = Button(root,text = "修改规则" , font=module,command=lambda :modify_rules(table))
add_rules = Button(root, text = "添加规则" ,command = add_rules, font=module)
remove_rules_Button = Button(root,text = "删除规则" ,font = module,command = lambda :remove_rules(table))
run_projetc = Button(root, text = "开启防火墙" ,font = module,command=run_project)
stop_project = Button(root, text= "关闭防火墙" ,font = module,command=stop_project)
output = Button(root,text="导出规则", font = module,command=lambda : export_to_csv(table))
check_log = Button(root, text='查看日志' ,font= module, command=check_log)
input = Button(root, text='导入规则', font=module,command=lambda :input_csv(table))
# 展示按钮
modify_rules_button.place(x = 190, y = 20)
add_rules.place(x=20,y=20)
remove_rules_Button.place(x = 360, y = 20)
run_projetc.place(x = 530, y = 20)
stop_project.place(x = 700 , y = 20)
output.place(x = 870, y = 20)
check_log.place(x = 870, y = 400)
input.place(x = 20, y=400)
# 插入规则表格
columns = ['Number','SADDR','SPORT','DADDR','DPORT','INTERFACE','TIME_BEGIN','TIME_END','PROTOCOL','icmp subtype']
table = ttk.Treeview(
    master=root, height = 15,columns=columns,show='headings',
)
table.heading(column='Number',text='Number',anchor='w')
table.heading('SADDR',text='SADDR')
table.heading('SPORT', text='SPORT')
table.heading('DADDR',text='DADDR')
table.heading('DPORT', text='DPORT')
table.heading('INTERFACE', text='INTERFACE')
table.heading('TIME_BEGIN', text='TIME_BEGIN')
table.heading('TIME_END', text='TIME_END')
table.heading('PROTOCOL', text='PROTOCOL')
table.heading('icmp subtype' ,text= 'icmp subtype')
table.column('Number', width=100 ,minwidth=100,anchor='s')
table.column('SADDR', width=100 ,minwidth=100,anchor='s')
table.column('SPORT', width=100 ,minwidth=100,anchor='s')
table.column('DADDR', width=100 ,minwidth=100,anchor='s')
table.column('DPORT', width=100 ,minwidth=100,anchor='s')
table.column('INTERFACE', width=100 ,minwidth=100,anchor='s')
table.column('TIME_BEGIN', width=100 ,minwidth=100,anchor='s')
table.column('TIME_END', width=100 ,minwidth=100,anchor='s')
table.column('PROTOCOL', width=100 ,minwidth=100,anchor='s')
table.column('icmp subtype' ,width=100,minwidth=100,anchor='s')
table.place(x=20, y=70)

#show the window
root.mainloop()









