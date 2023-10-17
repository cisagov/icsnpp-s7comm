signature dpd_s7comm_tcp {
  ip-proto == tcp
  dst-port == 102
  payload /^\x03\x00[\x00-\xff]{3}[\x10\x20\x50\x60\x70\x80\xc0\xd0\xe0\xf0]/
  enable "S7COMM_TCP"
}