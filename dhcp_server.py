##@file dhcp_server.py
##@brief Этот файл содержит реализацию простого DHCP-сервера на Python.

import socket
##@package socket
#Модуль для работы с сетевыми сокетами.
#Предоставляет классы и методы для создания и управления сетевыми соединениями.

import datetime
##@package datetime
#Модуль для работы с датой и временем.

import sys
##@package sys
#Модуль для работы с системными функциями и параметрами.

import json
##@package json
#Модуль для работы с JSON-файлами.

import binascii
##@package binascii
#Модуль для преобразования бинарных данных в текстовые и обратно.

import signal
##@package signal
#Модуль для обработки сигналов операционной системы, таких как прерывания.

import os
##@package os
#Модуль для работы с операционной системой, включая доступ к файловой системе.


##@class DHCPServer
##@brief Класс для реализации простого DHCP-сервера.
class DHCPServer:
 ##Конструктор класса DHCPServer.
 #@param port Порт для сервера (по умолчанию 67).
 #@param ip_address IP-адрес для сервера (по умолчанию 0.0.0.0).
 #@param output_file Файл для записи логов.
 #@param name_configuration Файл конфигурации сервера.
    def __init__(self, port=67, ip_address='0.0.0.0', output_file="output.txt", name_configuration="configuration.json"):
        self.port = port
        self.ip_address = ip_address
        self.output_file = output_file
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.should_stop = False 
        self.package_dhcp_transcript = None
        self.Configuration=read_json_file(name_configuration)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if os.path.exists('busy_ip_addresses_dhcp.json'):
            self.available_ips=read_json_file('busy_ip_addresses_dhcp.json')
        else:
            self.available_ips=[]

        signal.signal(signal.SIGINT, self.signal_handler)
    
 ###@brief Метод для обработки сигнала остановки сервера.
 #@param [in] sig Сигнал операционной системы.
 #@param [in] frame Контекст выполнения программы.
    def signal_handler(self, sig, frame):
        self.socket.close()
        self.log_dhcp_server("Received SIGINT, stopping DHCP server gracefully.")
        self.should_stop = True 
        sys.exit(0)

 ###@brief Метод для записи логов DHCP-сервера.
 #@param [in, out] log Строка с сообщением для записи в лог.
    def log_dhcp_server(self, log):
        now = datetime.datetime.now()
        formatted_time = now.strftime('%Y-%m-%d %H:%M:%S')
        with open(self.output_file, 'a+') as f:
            f.write(f"{formatted_time}: {log}\n")
    
 ##@brief Метод для запуска DHCP-сервера.
    def start(self):
        try:
            self.socket.bind((self.ip_address, self.port))
            self.log_dhcp_server(f"The DHCP server is running on {self.ip_address}:{self.port}")
            received_data = b''
            while not self.should_stop: 
                data, addr = self.socket.recvfrom(1024)
                received_data += data
                self.log_dhcp_server(f"Do ff")
             #Check if the 0xFF byte is contained in the received data
                if b'\xff' in data:
                 #Find the index of the first occurrence of the 0xFF byte
                    index = received_data.index(b'\xff')
                    
                 #Trim the data up to and including the first occurrence of 0xFF
                    package_dhcp = received_data[:index + 1]
                self.package_dhcp_transcript = PakageDhcp(binascii.hexlify(package_dhcp).decode('utf-8'))
                
                if b'\x35' in package_dhcp:
                    index = package_dhcp.index(b'\x35') + 2

                    if package_dhcp[index] == 1:
                        self.socket.sendto(binascii.unhexlify(self.dhcp_server_offer()), (self.package_dhcp_transcript.process_dhcp_message(message_type='02'),self.port+1)) #offer
                    if package_dhcp[index] == 3:
                        Num_Request = self.package_dhcp_transcript.option
                        Request_IP_addres = Num_Request[Num_Request.find("32")+4:Num_Request.find("32")+12]
                        if self.check_dhcp_packet_range_nack_or_pack(int(self.convert_ip_to_hex_format(self.Configuration['START_IP_ADDRESS']),16), int(self.convert_ip_to_hex_format(self.Configuration['START_IP_END']),16), int(Request_IP_addres,16)):
                            self.available_ips.append(int(Request_IP_addres,16))
                            write_to_json_file(self.available_ips, 'busy_ip_addresses_dhcp.json')
                            self.socket.sendto(binascii.unhexlify(self.dhcp_server_pack(Request_IP_addres)), (self.package_dhcp_transcript.process_dhcp_message(message_type='05'),self.port+1)) #pack
                        else:
                            self.socket.sendto(binascii.unhexlify(self.dhcp_server_nack()), (self.package_dhcp_transcript.process_dhcp_message(message_type='06'),self.port+1)) #nack
                            self.socket.sendto(binascii.unhexlify(self.dhcp_server_offer()), (self.package_dhcp_transcript.process_dhcp_message(message_type='02'),self.port+1)) #offer
                received_data = b''
                
        except OSError as e:
            self.log_dhcp_server(f'Error when starting the server: {e}')

        finally:
            self.socket.close()
            self.log_dhcp_server('DHCP server stopped')  
    
 ##@brief Метод для проверки, находится ли IP-адрес в заданном диапазоне и доступен ли он.
 #@param [in] ip_start Начальный IP-адрес.
 #@param [in] ip_end Конечный IP-адрес.
 #@param [in] num Проверяемый IP-адрес.
 #@return True, если IP-адрес находится в диапазоне и доступен, иначе False.
    def check_dhcp_packet_range_nack_or_pack(self, ip_start, ip_end, num):
     #Check if num is within the range [ip_start, ip_end]
        if ip_start <= num <= ip_end:
         #If num is within the range, check its presence in the array
            if not num in self.available_ips:
                return True  #Return True if num is found in the array
        return False  #Return False if num is out of range or not found in the array
    
 ##@brief Метод для формирования DHCP-пакета с предложением IP-адреса (OFFER).
 #@return Сформированный DHCP-пакет в формате hex.
    def dhcp_server_offer(self):
        time_ip= hex(int(self.Configuration['TIME_IP']))[2:]
        temp_dhcp_pacet = self.package_dhcp_transcript
        option = [
        '350102',  #Option (53) DHCP Message Type
        '3604', self.convert_ip_to_hex_format(self.Configuration['IP_DHCP']),  #Option (54) DHCP Server Identifier
        '3304',(8-len(time_ip))*'0'+time_ip,  #Option (51) IP Address Lease Time
        '0104', self.convert_ip_to_hex_format(self.Configuration['MASK_DHCP']),  #Option (1) Subnet Mask
        '0304', self.convert_ip_to_hex_format(self.Configuration['IP_ROUTER']),  #Option (3) Router
        '0608', self.convert_ip_to_hex_format(self.Configuration['IP_DNS']) + '00000000'  #Option (6) Domain Name Server
        ]
        end = 'ff'

        temp_dhcp_pacet.message_type = '02'
        temp_dhcp_pacet.your_client_ip_address=self.find_available_ip_offer(int(self.convert_ip_to_hex_format(self.Configuration['START_IP_ADDRESS']),16), int(self.convert_ip_to_hex_format(self.Configuration['START_IP_END']),16))
        
        result = ''
        for name, value in vars(temp_dhcp_pacet).items():
            if name != 'option':
                result+=value
            else:
                break
        
        return result + ''.join(option) + end

 ##@brief Метод для формирования DHCP-пакета с подтверждением (ACK).
 #@param [in] Request_IP_addres Запрашиваемый IP-адрес.
 #@return Сформированный DHCP-пакет в формате hex.
    def dhcp_server_pack(self,Request_IP_addres):
        time_ip= hex(int(self.Configuration['TIME_IP']))[2:]
        temp_dhcp_pacet = self.package_dhcp_transcript
        option = [
        '350105',  #Option (53) DHCP Message Type
        '3604', self.convert_ip_to_hex_format(self.Configuration['IP_DHCP']),  #Option (54) DHCP Server Identifier
        '3304',(8-len(time_ip))*'0'+time_ip,  #Option (51) IP Address Lease Time
        '0104', self.convert_ip_to_hex_format(self.Configuration['MASK_DHCP']),  #Option (1) Subnet Mask
        '0304', self.convert_ip_to_hex_format(self.Configuration['IP_ROUTER']),  #Option (3) Router
        '0608', self.convert_ip_to_hex_format(self.Configuration['IP_DNS']) + '00000000'  #Option (6) Domain Name Server
        ]
        end = 'ff'

        temp_dhcp_pacet.message_type = '02'
        temp_dhcp_pacet.your_client_ip_address=Request_IP_addres
        
        result = ''
        for name, value in vars(temp_dhcp_pacet).items():
            if name != 'option':
                result+=value
            else:
                break
        
        return result + ''.join(option) + end

 ##@brief Метод для формирования DHCP-пакета с отказом (NACK).
 #@return Сформированный DHCP-пакет в формате hex.
    def dhcp_server_nack(self):
        temp_dhcp_pacet = self.package_dhcp_transcript
        option = [
        '350106',  #Option (53) DHCP Message Type
        '3604', self.convert_ip_to_hex_format(self.Configuration['IP_DHCP']),  #Option (54) DHCP Server Identifier
        '381561646472657373206e6f7420617661696c61626c65'  #Option (56) Message
        ]
        end = 'ff'

        temp_dhcp_pacet.message_type = '02'
        
        result = ''
        for name, value in vars(temp_dhcp_pacet).items():
            if name != 'option':
                result+=value
            else:
                break
        
        return result + ''.join(option) + end
        
 ##@brief Поиск доступного IP-адреса для предложения
 #@param [in] start_ip Начальный IP-адрес диапазона
 #@param [in] end_ip Конечный IP-адрес диапазона
 #@return Доступный IP-адрес в шестнадцатеричном формате
    def find_available_ip_offer(self,start_ip, end_ip):
        for ip in range(start_ip, end_ip + 1):
            if ip not in self.available_ips:
                return (8 - len(hex(ip)[2:])) * '0' + hex(ip)[2:]
    
 ##@brief Закрытие сокета и завершение работы сервера
 #@return None
    def close(self):
        self.socket.close()
        self.log_dhcp_server("Received, stopping DHCP server gracefully.")
        self.should_stop = True 
        sys.exit(0)
    
 ##@brief Конвертация IP-адреса в шестнадцатеричный формат
 #@param [in] ip_address IP-адрес для конвертации
 #@return Строка, представляющая IP-адрес в шестнадцатеричном формате
    def convert_ip_to_hex_format(self, ip_address):
        hex_to_10 = ip_address
        array_item_hex = [hex(int(elem))[2:] for elem in hex_to_10.split('.')]
        arr_with_zero = ['0' + item if len(item) < 2 else item for item in array_item_hex]
        return ''.join(arr_with_zero)

##@class PakageDhcp
##@brief Инициализация объекта DHCP пакета и чтение конфигурационного файла 
#@param [in] package Байтовая строка, представляющая содержимое пакета DHCP
#@param [in] name_configuration Имя файла конфигурации JSON(по умолчанию "configuration.json")
#@return None
class PakageDhcp:
    def __init__(self,package,name_configuration="configuration.json"):
        self.message_type = package[:1*2]
        self.hardware_type = package[1*2:2*2]
        self.hardware_address_length = package[2*2:3*2]
        self.hops = package[3*2:4*2]
        self.transaction_id = package[4*2:8*2]
        self.seconds_elapsed = package[8*2:10*2]
        self.bootp_flags = package[10*2:12*2]
        self.client_ip_address = package[12*2:16*2]
        self.your_client_ip_address = package[16*2:20*2]
        self.next_server_ip_address = package[20*2:24*2]
        self.relay_agent_ip_address = package[24*2:28*2]
        self.client_mac_address = package[28*2:34*2]
        self.client_hardware_address_padding = package[34*2:44*2]
        self.server_host = package[44*2:108*2]
        self.boot_file = package[108*2:236*2]
        self.magick_cookie = package[236*2:240*2]
        self.option = package[240*2:-1*2]
        self.Configuration=read_json_file(name_configuration)

 ##@brief Обработка DHCP-сообщения с различными параметрами адресации
 #@param [in] giaddr Адрес DHCP relay (по умолчанию 00000000)
 #@param [in] message_type Тип сообщения DHCP
 #@return Строка с адресом назначения в формате IPv4
    def process_dhcp_message(self, giaddr = '00000000',message_type='00'):
        if giaddr != '00000000':
         #Server forwards all responses to DHCP relay messages to the BOOTP relay address
            target_address = giaddr
        elif self.client_ip_address != '00000000':
         #Server sends DHCPOFFER and DHCPACK messages to the individual client address self.client_ip_address
            target_address = self.client_ip_address
        elif self.bootp_flags == '0000' and giaddr == '00000000' and self.client_ip_address == '00000000':
         #Server sends DHCPOFFER and DHCPACK messages to the broadcast address 0xffffffff
            target_address = self.apply_find_broadcast(self.Configuration['IP_DHCP'], self.Configuration['MASK_DHCP'])

        elif self.bootp_flags != '0000' and giaddr == '00000000' and self.client_ip_address == '00000000':
         #Server sends DHCPOFFER and DHCPACK messages to the individual client hardware address and self.your_client_ip_address
            target_address = self.your_client_ip_address  #Assuming self.your_client_ip_address is defined elsewhere in the code
        else:
         #In all other cases where giaddr = 0, the server sends DHCPNAK messages to the broadcast address 0xffffffff
            target_address = self.apply_find_broadcast(self.Configuration['IP_DHCP'], self.Configuration['MASK_DHCP'])

        if  message_type == '06' or message_type == '05':
         #Sending DHCPNAK message
            target_address = self.apply_find_broadcast(self.Configuration['IP_DHCP'], self.Configuration['MASK_DHCP'])  #DHCPNAK is always sent to the broadcast address
        
        return ".".join([str(int(target_address[i:i+2], 16)) for i in range(0, len(target_address), 2)])
    
 ##@brief Нахождение широковещательного адреса на основе IP-адреса и маски подсети
 #@param [in] ip IP-адрес в формате строки
 #@param [in] mask Маска подсети в формате строки
 #@return Строка, представляющая широковещательный адрес в шестнадцатеричном формате
    def apply_find_broadcast(self, ip, mask):
         #Convert the string representation of the IP address into a list of numbers
        ip = [int(elem) for elem in ip.split('.')]
        
     #Convert the string representation of the subnet mask into a list of numbers
        mask = [int(elem) for elem in mask.split('.')]
        
     #Perform bitwise NOT operation on each element of the subnet mask
        inverse_mask = [~int(elem) & 0xFF for elem in mask]
        
     #Apply the subnet mask to the IP address
        result = [hex((ip[i]&mask[i])+inverse_mask[i])[2:] for i in range(0,4)]
        arr_with_zero = ['0' + item if len(item) < 2 else item for item in result]
        return ''.join(arr_with_zero)

##@brief Чтение данных из JSON файла
#@param [in] file_name Имя файла JSON для чтения
#@return Словарь с данными JSON файла, если файл существует и правильный, иначе None
def read_json_file(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        DHCPServer.log_dhcp_server(f"File '{file_name}' no")
        return None
    except json.JSONDecodeError:
        DHCPServer.log_dhcp_server(f"Error JSON file'{file_name}'.")
        return None


##@brief Запись данных в JSON файл
#@param [in] data Данные для записи в JSON
#@param [in] file_path Путь к файлу JSON
#@return True, если запись успешна, иначе False
def write_to_json_file(data, file_path):
    try:
        with open(file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)  #Записываем данные в файл с отступами для удобства чтения
        return True
    except Exception as e:
        DHCPServer.log_dhcp_server(f"Error file JSON file: {e}")
        return False


if __name__ == "__main__":
    server_default = DHCPServer(output_file="DHCPoutput.txt", name_configuration="configuration.json")
    server_default.start()