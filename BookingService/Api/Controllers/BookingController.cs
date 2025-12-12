using Application.Bookings.Commands;
using Application.Bookings.Queries;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace BookingService.Controllers
{
    [ApiController]
    [Route("api/bookings")]
    public class BookingsController : ControllerBase
    {
        private readonly IMediator _mediator;

        public BookingsController(IMediator mediator)
        {
            _mediator = mediator;
        }

        /// <summary>
        /// Create new booking
        /// </summary>
        /// <remarks>
        /// This endpoint create a new booking
        /// </remarks>
        /// <response code="200">Returns the list of apartments</response>
        /// <response code="500">Server error</response>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> Create(CreateBookingCommand command)
        {
            var id = await _mediator.Send(command);
            return Ok(new { id });
        }

        [HttpPost("{id}/reschedule")]
        public async Task<IActionResult> Update(Guid id, RescheduleBookingCommand command)
        {
            command.Id = id;
            return Ok(await _mediator.Send(command));
        }

        [HttpPost("{id}/cancel")]
        public async Task<IActionResult> Cancel(Guid id)
        {
            return Ok(await _mediator.Send(new CancelBookingCommand { Id = id }));
        }

        [HttpPost("{id}/confirm")]
        public async Task<IActionResult> Confirm(Guid id)
        {
            return Ok(await _mediator.Send(new ConfirmBookingCommand { Id = id }));
        }

        [HttpGet("apartment/{id}")]
        public async Task<IActionResult> Get(Guid id)
        {
            return Ok(await _mediator.Send(new GetBookingsByApartmentIdQuery { Id = id }));
        }

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            return Ok(await _mediator.Send(new GetAllBookingsQuery()));
        }
    }
}
