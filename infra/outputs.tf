output "public_ip" {
  description = "Public IP of the TAKE server"
  value       = aws_instance.take_server.public_ip
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh -i <your-key.pem> ec2-user@${aws_instance.take_server.public_ip}"
}

output "server_url" {
  description = "TAKE API server URL"
  value       = "http://${aws_instance.take_server.public_ip}:5000"
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.take_server.id
}
