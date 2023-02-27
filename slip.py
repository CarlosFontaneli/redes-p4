class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.trash = ""

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):

        ds = b''
        list_data = list(datagrama)

        for i in range(len(list_data)):
            if list_data[i] == 0xc0:
                ds += bytes([0xdb])
                ds += bytes([0xdc])

            elif list_data[i] == 0xdb:
                ds += bytes([0xdb])
                ds += bytes([0xdd])

            else:
                ds += bytes([list_data[i]])

        self.linha_serial.enviar(
            bytes([0xc0]) + ds + bytes([0xc0]))
        pass

    def __raw_recv(self, dados):
        self.trash += dados.hex()

        while self.trash.find("c0") != -1:

            p = self.trash.partition("c0")[0]
            self.trash = self.trash.partition("c0")[2]

            if p == "":
                continue

            pe = ""

            i = 0
            while i+1 < len(p):
                if p[i:i+2] == "db":
                    i += 2
                    if p[i:i+2] == "dc":
                        pe = pe + "c0"
                    if p[i:i+2] == "dd":
                        pe = pe + "db"
                else:
                    pe = pe + p[i:i+2]
                i += 2
            try:
                self.callback(bytes.fromhex(pe))

            except:
                pass
        pass
