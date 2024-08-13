# PixelGuard AI (AI IMAGE PROTECT)

## Introduction
AI scraping involves the automated collection of images from the internet for training AI models. This practice can lead to unauthorized use of personal or copyrighted images. PixelGuard AI aims to protect your images from such scraping and other AI training (like 'deepfakes') by applying various invisible techniques that interfere with AI processing while preserving the visual quality for human viewers (as much as possible).

## Example Results

Here's an example of PixelGuard AI in action:

| Unprotected Image | Protected Image |
|:-----------------:|:---------------:|
| ![Unprotected](efcsdzecvzdscz.png) | ![Protected](protected_efcsdzecvzdscz.png) |

As you can see, the protected image looks virtually identical to the human eye, but contains invisible protections against AI scraping and processing.

## Features
- **Multiple 'Invisible' Protection Techniques**:
  - DCT (Discrete Cosine Transform) Watermarking
  - Wavelet-based Watermarking
  - Fourier Transform Watermarking
  - Adversarial Perturbation
  - Colour Jittering
  - Invisible QR Code Embedding
  - Steganography
- **Digital Signature and Hash Verification** for tamper detection
- **Perceptual Hash** for content change detection
- **Timestamp Verification** to check the age of protection
- **Support for Multiple Image Formats**: JPEG, PNG, BMP, TIFF, WebP
- **Batch Processing**
- **User-friendly GUI** for easy interaction
- **Verification Tool** to check if an image has been protected and/or tampered with

## System Requirements
- Python 3.7 or higher, but Python <= 3.11 is required
- Compatible with Windows, macOS, and Linux

## Installation
1. Ensure you have Python 3.7 - 3.11 installed. Python 3.11 is the latest supported version. You can check your Python version by running:
   ```
   python --version
   ```

2. Clone this repository:
   ```
   git clone https://github.com/captainzero93/Protect-Images-from-AI-PixelGuard.git
   cd Protect-Images-from-AI-PixelGuard
   ```

3. Set up a virtual environment:
   - For Windows:
     ```
     python -m venv venv
     venv\Scripts\activate
     ```
   - For macOS and Linux:
     ```
     python3 -m venv venv
     source venv/bin/activate
     ```

4. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

Again: This project is not currently compatible with Python 3.12 or later due to dependency constraints. Please use Python 3.11 or earlier.

## Usage
Activate your virtual environment (if not already activated), then run the script:
```
python imgprotect.py
```
This will open a GUI with three main options:
1. **Protect Single Image**: Select a single image to protect.
2. **Batch Protect Images**: Select multiple images to protect in batch.
3. **Verify Image**: Check if an image has been protected and if it has been tampered with.

### Protecting Images
1. Click on "Protect Single Image" or "Batch Protect Images".
2. Select the image(s) you want to protect.
3. Choose an output directory for the protected images.
4. Wait for the process to complete. A success message will appear when done.

### Verifying Images
1. Click on "Verify Image".
2. Select the image you want to verify.
3. The tool will check if the image contains protection information, if it has been tampered with, and how long ago it was protected.

## Customization
The GUI allows users to adjust the strength of each protection technique. Use the sliders to fine-tune the balance between protection effectiveness and image quality.

## How It Works
1. **DCT Watermarking**: Embeds a watermark in the frequency domain of the blue channel.
2. **Wavelet-based Watermarking**: Embeds a watermark in the wavelet domain of the green channel.
3. **Fourier Transform Watermarking**: Applies a watermark in the frequency domain of the red channel.
4. **Adversarial Perturbation**: Adds minor perturbations to the image that are designed to confuse AI models.
5. **Color Jittering**: Randomly adjusts brightness, contrast, and saturation to add another layer of protection.
6. **Invisible QR Code**: Embeds an invisible QR code containing image information.
7. **Steganography**: Hides additional protection data within the image itself.
8. **Digital Signature**: Signs the entire image to detect any tampering.
9. **Hash Verification**: Uses both a cryptographic hash and a perceptual hash to check if the image has been altered.
10. **Timestamp Verification**: Checks when the image was protected and suggests re-protection if it's too old.

These techniques work together to create multiple layers of protection that are extremely difficult for AI training algorithms to remove or ignore, while remaining imperceptible to human viewers.

## Security Analysis

1. **Robustness**: The combination of multiple techniques provides a strong defense against AI scraping. However, determined adversaries with significant resources might still find ways to remove or bypass some protections. Regular updates to the protection algorithms will help stay ahead of potential threats.

2. **Cryptographic Security**: The use of RSA-2048 for digital signatures provides strong security. However, key management is a potential weak point as keys are generated per session. Future versions could implement a more robust key management system.

3. **Steganography**: The current implementation uses a simple Least Significant Bit (LSB) steganography technique. While effective for casual protection, it may be detectable by advanced statistical analysis. Future versions could implement more sophisticated steganography techniques for increased security.

4. **Reversibility**: Most of the protection techniques applied are not easily reversible. This is generally a positive aspect for security but may be a limitation in some use cases where users need to recover the original, unprotected image.

5. **Perceptual Impact**: While the techniques aim to be imperceptible to humans, there may ( mostly always ) be slight visual changes, especially at higher protection strengths. Users should balance protection strength with acceptable visual quality.

6. **Metadata Preservation**: The current implementation may not preserve all original image metadata. Future versions could focus on maintaining important metadata while still applying protections.

## Potential Improvements

1. **Modular Architecture**: Refactoring the protection techniques into separate modules could improve maintainability and allow for easier addition of new techniques or updates to existing ones.

2. **Advanced Steganography**: Implementing more sophisticated steganography techniques could improve the hiding of metadata and increase resistance to statistical analysis.

3. **GPU Acceleration**: Given the computational intensity of some protection techniques, implementing GPU acceleration could significantly improve performance, especially for batch processing of large images.

4. **Adaptive Protection**: Developing a system that analyzes images and automatically adjusts protection strength based on content may optimize the balance between protection effectiveness and visual quality.

5. **Comprehensive Testing Suite**: Adding a suite of unit and integration tests would improve reliability, ease future development, and help quickly identify any regressions when making updates.

6. **Enhanced Key Management**: Implementing a more robust key management system could improve the overall security of the cryptographic operations.

7. **Machine Learning Integration**: Incorporating machine learning models to detect and adapt to new AI scraping techniques could provide more dynamic and future-proof protection.

8. **API Development**: Creating an API for the core functionality would allow for easier integration with other software or web services.

## Updating
To update PixelGuard AI to the latest version:
1. Pull the latest changes from the repository:
   ```
   git pull origin main
   ```
2. Reinstall requirements in case of any changes:
   ```
   pip install -r requirements.txt
   ```

## Troubleshooting
- If you encounter "ModuleNotFoundError", ensure all dependencies are correctly installed.
- For image format errors, check that your image is in one of the supported formats.
- If protection seems too strong or weak, adjust the settings using the GUI sliders.

## Limitations
While PixelGuard AI significantly increases protection against AI scraping, it may not be 100% effective against all current and future AI technologies. It's designed to strike a balance between protection and maintaining image quality.

## Contributing
We welcome contributions! If you'd like to contribute:
1. Fork the repository
2. Create a new branch for your feature
3. Commit your changes
4. Push to your branch
5. Create a new Pull Request

Please ensure your code adheres to our coding standards and includes appropriate tests.

## Caution
While these protection methods significantly increase the difficulty of using the images for AI training, no protection method is perfect. Always be cautious about sharing personal images online.

## Citation
If you use PixelGuard AI, as software or protection concepts in your research or projects, please cite it as follows:
```
[captainzero93]. (2024). PixelGuard AI. GitHub. https://github.com/captainzero93/Protect-Images-from-AI-PixelGuard
```

## License

This project is available under a dual license:

1. **Non-Commercial Use**: For non-commercial purposes, this project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). This allows for sharing and adaptation of the code for non-commercial purposes, with appropriate attribution.

2. **Commercial Use**: Any commercial use, including but not limited to selling the code, using it in commercial products or services, or any revenue-generating activities, requires a separate commercial license. You must contact the project owner to discuss terms and potential payment.

Please see the [LICENSE](LICENSE) file for full details on both licenses.

For commercial licensing inquiries, please contact: joe.faulkner.0@gmail.com

By using this project, you agree to abide by the terms of the appropriate license based on your intended use.
