io.on("connection", socket => {

    socket.on("offer", data => {
        socket.broadcast.emit("offer", data);
    });

    socket.on("answer", data => {
        socket.broadcast.emit("answer", data);
    });

    socket.on("ice", data => {
        socket.broadcast.emit("ice", data);
    });

});
