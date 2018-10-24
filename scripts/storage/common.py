def read_messages(f, message_type):
    while True:
        message_size_line = f.readline()
        if not message_size_line:
            break
        message_size = int(message_size_line.strip())
        message_raw = f.read(message_size)
        if len(message_raw) != message_size:
            print >>sys.stderr, 'short read'
            break
        item = message_type()
        item.ParseFromString(message_raw)
        yield item
