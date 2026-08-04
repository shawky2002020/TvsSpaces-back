-- Create users table
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(191) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'ROLE_USER',
    login_count INT NOT NULL DEFAULT 0,
    last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create spaces table
CREATE TABLE spaces (
    id VARCHAR(50) PRIMARY KEY,
    type VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    image_url VARCHAR(255),
    capacity INT NOT NULL,
    hourly_price DOUBLE NOT NULL,
    half_day_price DOUBLE NOT NULL,
    day_price DOUBLE NOT NULL
);

-- Create space_images table
CREATE TABLE space_images (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    space_id VARCHAR(50) NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    FOREIGN KEY (space_id) REFERENCES spaces(id) ON DELETE CASCADE
);

-- Create space_amenities table
CREATE TABLE space_amenities (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    space_id VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    icon VARCHAR(50) NOT NULL,
    FOREIGN KEY (space_id) REFERENCES spaces(id) ON DELETE CASCADE
);

-- Create bookings table
CREATE TABLE bookings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    reference VARCHAR(50) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    space_id VARCHAR(50) NOT NULL,
    plan VARCHAR(20) NOT NULL,
    start_at TIMESTAMP NOT NULL,
    end_at TIMESTAMP NOT NULL,
    reserved_units INT NOT NULL,
    unit_price DOUBLE NOT NULL,
    total_price DOUBLE NOT NULL,
    status VARCHAR(20) NOT NULL,
    payment_method VARCHAR(50) NOT NULL,
    payment_status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    version INT NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (space_id) REFERENCES spaces(id) ON DELETE CASCADE
);

-- Create refresh_sessions table
CREATE TABLE refresh_sessions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(191) NOT NULL UNIQUE,
    token_hash VARCHAR(255) NOT NULL,
    expiry_date TIMESTAMP NOT NULL
);

-- Seed Space 1 (Shared Desk)
INSERT INTO spaces (id, type, name, slug, description, image_url, capacity, hourly_price, half_day_price, day_price)
VALUES ('1', 'desk', 'Shared Desk', 'shared-desk', 'Flexible seating in our open workspace areas.', 'assets/imgs/spaces/shared2.jpg', 7, 40, 35, 32);

INSERT INTO space_images (space_id, image_url) VALUES 
('1', 'assets/imgs/spaces/shared0.jpg'),
('1', 'assets/imgs/spaces/shared1.jpg'),
('1', 'assets/imgs/spaces/shared2.jpg'),
('1', 'assets/imgs/spaces/shared3.jpg'),
('1', 'assets/imgs/spaces/shared4.jpg');

INSERT INTO space_amenities (space_id, name, icon) VALUES 
('1', 'Shared workspace', 'users'),
('1', 'High-speed Wi-Fi', 'wifi'),
('1', 'Power outlets', 'plug'),
('1', 'Storage lockers', 'lock');

-- Seed Space 2 (Solo Desk)
INSERT INTO spaces (id, type, name, slug, description, image_url, capacity, hourly_price, half_day_price, day_price)
VALUES ('2', 'desk', 'Solo Desk', 'solo-desk', 'Your own desk in a shared office environment.', 'assets/imgs/spaces/solo0.jpg', 1, 50, 45, 42);

INSERT INTO space_images (space_id, image_url) VALUES 
('2', 'assets/imgs/spaces/solo0.jpg'),
('2', 'assets/imgs/spaces/solo1.jpg'),
('2', 'assets/imgs/spaces/solo2.jpg'),
('2', 'assets/imgs/spaces/solo3.jpg');

INSERT INTO space_amenities (space_id, name, icon) VALUES 
('2', 'Personal workspace', 'user'),
('2', 'Under-desk storage', 'archive'),
('2', 'Monitor support', 'desktop'),
('2', 'Member perks', 'star');

-- Seed Space 3 (PC Station)
INSERT INTO spaces (id, type, name, slug, description, image_url, capacity, hourly_price, half_day_price, day_price)
VALUES ('3', 'desk', 'PC Station', 'pc-station', 'Fully equipped workstation with high-performance PC.', 'assets/imgs/spaces/pc-station0.jpg', 3, 60, 55, 52);

INSERT INTO space_images (space_id, image_url) VALUES 
('3', 'assets/imgs/spaces/pc-station1.jpg'),
('3', 'assets/imgs/spaces/pc-station2.jpg'),
('3', 'assets/imgs/spaces/pc-station3.jpg');

INSERT INTO space_amenities (space_id, name, icon) VALUES 
('3', 'High-performance PC', 'desktop'),
('3', 'Dual monitors', 'tv'),
('3', 'Ergonomic chair', 'chair'),
('3', 'Software suite', 'code');

-- Seed Space 4 (Team Room)
INSERT INTO spaces (id, type, name, slug, description, image_url, capacity, hourly_price, half_day_price, day_price)
VALUES ('4', 'room', 'Team Room', 'team-room', 'Private office space for teams of 2-4 people.', 'assets/imgs/spaces/sm-meeting0.jpg', 1, 120, 115, 110);

INSERT INTO space_images (space_id, image_url) VALUES 
('4', 'assets/imgs/spaces/sm-meeting0.jpg'),
('4', 'assets/imgs/spaces/sm-meeting1.jpg'),
('4', 'assets/imgs/spaces/sm-meeting2.jpg');

INSERT INTO space_amenities (space_id, name, icon) VALUES 
('4', 'Private space', 'lock'),
('4', 'Conference table', 'table'),
('4', 'Whiteboard', 'edit'),
('4', 'TV display', 'tv');

-- Seed Space 5 (Big Meeting Room)
INSERT INTO spaces (id, type, name, slug, description, image_url, capacity, hourly_price, half_day_price, day_price)
VALUES ('5', 'room', 'Big Meeting Room', 'big-meeting-room', 'Spacious meeting room for larger teams and presentations.', 'assets/imgs/spaces/meeting2.jpg', 1, 200, 190, 185);

INSERT INTO space_images (space_id, image_url) VALUES 
('5', 'assets/imgs/spaces/meeting1.jpg'),
('5', 'assets/imgs/spaces/meeting2.jpg'),
('5', 'assets/imgs/spaces/meeting3.jpg'),
('5', 'assets/imgs/spaces/meeting4.jpg'),
('5', 'assets/imgs/spaces/meeting5.jpg');

INSERT INTO space_amenities (space_id, name, icon) VALUES 
('5', 'Conference setup', 'users'),
('5', 'Projector', 'film'),
('5', 'Sound system', 'volume-up'),
('5', 'Catering option', 'utensils');
